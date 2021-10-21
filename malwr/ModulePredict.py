#! /usr/bin/python2
import pefile
import os
import array
import math
import pickle
# from sklearn.externals import joblib
import joblib
import sys
import argparse

def get_entropy(data):
    if len(data) == 0:
        return 0.0
    stat = array.array('L', [0]*256)
    for x in data:
        stat[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in stat:
        if x:
            val = float(x) / len(data)
            entropy -= val*math.log(val, 2)

    return entropy

def resources_extraction(pe):
    """Extract src :
    [entropy, size]"""
    src = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                src.append([entropy, size])
        except Exception as e:
            return src
    return src

def version_extraction(pe):
    """Return version infos"""
    source = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    source[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                source[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
          source['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
          source['os'] = pe.VS_FIXEDFILEINFO.FileOS
          source['type'] = pe.VS_FIXEDFILEINFO.FileType
          source['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
          source['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
          source['signature'] = pe.VS_FIXEDFILEINFO.Signature
          source['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return source

def data_extraction(path):
    source = {}
    pe = pefile.PE(path)
    source['Machine'] = pe.FILE_HEADER.Machine
    source['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    source['Characteristics'] = pe.FILE_HEADER.Characteristics
    source['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    source['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    source['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    source['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    source['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    source['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    source['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        source['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        source['BaseOfData'] = 0
    source['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    source['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    source['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    source['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    source['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    source['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    source['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    source['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    source['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    source['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    source['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    source['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    source['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    source['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    source['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    source['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    source['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    source['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    source['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    source['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # Sections
    source['SectionsNb'] = len(pe.sections)
    entropy = list(map(lambda x:x.get_entropy(), pe.sections))
    source['SectionsMeanEntropy'] = sum(entropy)/float(len(entropy))
    source['SectionsMinEntropy'] = min(entropy)
    source['SectionsMaxEntropy'] = max(entropy)


    raw_sizes = list(map(lambda x:x.SizeOfRawData, pe.sections))
    source['SectionsMeanRawsize'] = sum(raw_sizes)/float(len(raw_sizes))
    source['SectionsMinRawsize'] = min(raw_sizes)
    source['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = list(map(lambda x:x.Misc_VirtualSize, pe.sections))
    source['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
    source['SectionsMinVirtualsize'] = min(virtual_sizes)
    source['SectionMaxVirtualsize'] = max(virtual_sizes)

    #Imports
    try:
        source['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = list(sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], []))
        source['ImportsNb'] = len(imports)
        source['ImportsNbOrdinal'] = len(list(filter(lambda x:x.name is None, imports)))
    except AttributeError:
        source['ImportsNbDLL'] = 0
        source['ImportsNb'] = 0
        source['ImportsNbOrdinal'] = 0

    #Exports
    try:
        source['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        # No export
        source['ExportNb'] = 0
    #src
    src= resources_extraction(pe)
    source['ResourcesNb'] = len(src)
    if len(src)> 0:
        entropy = list(map(lambda x:x[0], src))
        source['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
        source['ResourcesMinEntropy'] = min(entropy)
        source['ResourcesMaxEntropy'] = max(entropy)
        sizes = list(map(lambda x:x[1], src))
        source['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
        source['ResourcesMinSize'] = min(sizes)
        source['ResourcesMaxSize'] = max(sizes)
    else:
        source['ResourcesNb'] = 0
        source['ResourcesMeanEntropy'] = 0
        source['ResourcesMinEntropy'] = 0
        source['ResourcesMaxEntropy'] = 0
        source['ResourcesMeanSize'] = 0
        source['ResourcesMinSize'] = 0
        source['ResourcesMaxSize'] = 0

    # Load configuration size
    try:
        source['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        source['LoadConfigurationSize'] = 0


    # Version configuration size
    try:
        version_infos = version_extraction(pe)
        source['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        source['VersionInformationSize'] = 0
    return source
