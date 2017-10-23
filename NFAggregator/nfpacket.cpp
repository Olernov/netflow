#include "nfpacket.h"

NFPacket::NFPacket(FlowVersion v, CFileReader& fr, TemplateMap &tm, Aggregator* aggr) :
    version(v),
    fileReader(fr),
    aggregator(aggr),
    templateMap(tm),
    dataRecordsCount(0),
    templatesCount(0),
    bytesProcessed(VERSION_FIELD_SIZE) // since NFParser has already read Version field
{
    switch(version) {
    case NETFLOW_V9:
        TEMPLATE_SET_ID = 0;
        break;
    case IPFIX:
        TEMPLATE_SET_ID = 2;
        break;
    default:
        throw std::runtime_error("Unsupported version of Netflow");
    }
}

// returns count of records processed from flowset or -1 if no data available
int32_t NFPacket::ParseFlowSet()
{
    uint8_t *buffer;
    FlowSetHeader flowSetHeader;
    // read flowset header
    size_t stBytesRead = fileReader.ReadData(&buffer, sizeof(flowSetHeader));
    if (stBytesRead != sizeof(flowSetHeader)) {
        return -1;
    }
    bytesProcessed += stBytesRead;
    flowSetHeader.flowSetID = ntohs (*((u_short*)buffer));
    flowSetHeader.length = ntohs (*((u_short*)&(buffer[2])));
    if (flowSetHeader.length == 0) {
        return -1;
    }

    stBytesRead = fileReader.ReadData(&buffer, flowSetHeader.length - sizeof(flowSetHeader));
    bytesProcessed += stBytesRead;
    if (flowSetHeader.length - sizeof(flowSetHeader) != stBytesRead) {
        return -1;
    }

    uint32_t recordsProcessed = 0;
    // if FlowSet contains template description
    if (flowSetHeader.flowSetID == TEMPLATE_SET_ID) {
        recordsProcessed = ParseTemplateFlowSet(buffer,
                                                flowSetHeader.length - sizeof(flowSetHeader));
    }
    else if (flowSetHeader.flowSetID > 255) { // flowSet contains data
        uint64_t ulTmpltId = flowSetHeader.flowSetID;
        ulTmpltId |= static_cast<uint64_t>(GetDomainID()) << 32;
        auto iterTemplate = templateMap.find (ulTmpltId);
        if (iterTemplate != templateMap.end()) {
            uint32_t recordCount = (flowSetHeader.length - sizeof(flowSetHeader))
                    / iterTemplate->second->dataSize;
            FlowTemplate *nfTemplate = iterTemplate->second;
            ParseDataFlowSet(nfTemplate, buffer, recordCount);
            recordsProcessed = recordCount;
        }
    }
    return recordsProcessed;
}


int NFPacket::ParseTemplateFlowSet(uint8_t *buffer, size_t dataSize)
{
    std::map<uint64_t,FlowTemplate*>::iterator iterTemplate;
    int iRetVal = 0;
    FlowTemplate nfTemplate;
    size_t stReadInd = 0;
    uint64_t ulTmpltId;

    while (stReadInd < dataSize) {
        memset(&nfTemplate, 0, sizeof(nfTemplate));
        nfTemplate.templateID = (buffer[stReadInd++] << 8);
        nfTemplate.templateID += buffer[stReadInd++];
        nfTemplate.fieldCount = (buffer[stReadInd++] << 8);
        nfTemplate.fieldCount = buffer[stReadInd++];

        // check if template exists if list
        ulTmpltId = 0;
        ulTmpltId = nfTemplate.templateID;
        ulTmpltId |= static_cast<uint64_t>(GetDomainID()) << 32;
        templatesCount++;

        iterTemplate = templateMap.find (ulTmpltId);
        // if template with same ID is already stored
        if (iterTemplate != templateMap.end()) {
            // template found, check template identity
            if (iterTemplate->second->masterCopySize == dataSize) {
                if (memcmp(buffer, iterTemplate->second->masterCopy, dataSize) == 0) {
                        stReadInd += sizeof(FlowField) * nfTemplate.fieldCount;
                        ++iRetVal;
                        continue;
                }
            }
            // if we came here, templates are not identical
            // remove previous template
            delete[] iterTemplate->second->masterCopy;
            delete iterTemplate->second;
            templateMap.erase (iterTemplate);
        }

        // store template master copy
        nfTemplate.masterCopySize = dataSize;
        nfTemplate.masterCopy = new uint8_t[dataSize];
        memcpy(nfTemplate.masterCopy, buffer, dataSize);

        FlowTemplate *psoTmpTempl = new FlowTemplate;
        *psoTmpTempl = nfTemplate;
        FlowField *psoTmpField;

        uint32_t dwOffset = 0;
        psoTmpTempl->field = new FlowField*[nfTemplate.fieldCount];

        for (uint32_t i=0; i < nfTemplate.fieldCount; ++i) {
            psoTmpField = new FlowField;
            psoTmpField->offset = dwOffset;
            psoTmpField->fieldType = (buffer[stReadInd++] << 8);
            psoTmpField->fieldType += buffer[stReadInd++];
            psoTmpField->fieldSize =  (buffer[stReadInd++] << 8);
            psoTmpField->fieldSize += buffer[stReadInd++];
            dwOffset += psoTmpField->fieldSize;
            psoTmpTempl->dataSize += psoTmpField->fieldSize;
            psoTmpTempl->field[i] = psoTmpField;
        }

        ulTmpltId = 0;
        ulTmpltId = nfTemplate.templateID;
        ulTmpltId |= static_cast<uint64_t>(GetDomainID()) << 32;

        templateMap.insert(std::pair<uint64_t,FlowTemplate*>(ulTmpltId,psoTmpTempl));
        ++iRetVal;
    }

    return iRetVal;
}


void NFPacket::ParseDataFlowSet(
    FlowTemplate *nfTemplate,
    uint8_t *buffer,
    uint32_t recordCount)
{
    for (uint32_t i = 0; i < recordCount; ++i )	{
        DataRecord* dataRecord = new DataRecord;
        memset(dataRecord, 0 ,sizeof(DataRecord));
        bool parseRes = ParseDataRecord(buffer, nfTemplate, dataRecord);
        if (parseRes) {
            dataRecordsCount++;
            if (aggregator != nullptr) {
                aggregator->AddDataRecord(dataRecord);
            }
        }
        else {
            delete dataRecord;
        }
        buffer += nfTemplate->dataSize;
    }
}


bool NFPacket::ParseDataRecord(uint8_t *rawData, FlowTemplate *nfTemplate, DataRecord* dataRecord)
{
    for (size_t i = 0; i < nfTemplate->fieldCount; ++i) {
        switch (nfTemplate->field[i]->fieldType) {
        case IDS_IPV4_SRC_ADDR:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->srcIpAddr)) {
                return false;
            }
            break;
        case IDS_IPV4_DST_ADDR:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->dstIpAddr)) {
                return false;
            }
            break;
        case IDS_L4_SRC_PORT:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->srcPort)) {
                return false;
            }
            break;
        case IDS_L4_DST_PORT:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->dstPort)) {
                return false;
            }
            break;
        case IDS_IN_BYTES:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->inBytes)) {
                return false;
            }
            break;
        case IDS_OUT_BYTES:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->outBytes)) {
                return false;
            }
            break;
        case IDS_FIRST_SWITCHED:
            if (!ParseSwitchedTime(rawData, nfTemplate->field[i]->fieldSize, dataRecord->firstSwitched)) {
                return false;
            }
            break;
        case IDS_LAST_SWITCHED:
            if (!ParseSwitchedTime(rawData, nfTemplate->field[i]->fieldSize, dataRecord->lastSwitched)) {
                return false;
            }
            break;
        case IDS_FLOW_START_MILLISECONDS:
            if (!ParseDateTimeMs(rawData, nfTemplate->field[i]->fieldSize, dataRecord->firstSwitched)) {
                return false;
            }
            break;
        case IDS_FLOW_END_MILLISECONDS:
            if (!ParseDateTimeMs(rawData, nfTemplate->field[i]->fieldSize, dataRecord->lastSwitched)) {
                return false;
            }
            break;
        }
        rawData += nfTemplate->field[i]->fieldSize;
    }
    return true;
}


bool NFPacket::ParseDateTimeMs(uint8_t* rawData, int fieldSize, time_t& switchedTime)
{
    uint64_t dateTimeMs;
    if (!ReadInteger(rawData, fieldSize, dateTimeMs)) {
        return false;
    }
    switchedTime = dateTimeMs/1000;
    return true;
}
