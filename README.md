# DataProcessingVirus
Columns with low variability: e_cblp, e_cp, e_cparhdr, e_minalloc, e_maxalloc, e_sp, e_ovno, SizeOfHeapReserve, SizeOfHeapCommit
Columns with high variability: e_lfanew, Machine, NumberOfSections, TimeDateStamp, SizeOfOptionalHeader, Characteristics, Magic, MajorLinkerVersion, MinorLinkerVersion, SizeOfCode, SizeOfInitializedData, SizeOfUnitializedData, AddressOfEntryPoint, BaseOfCode, ImageBase, SectionAlignment, FileAlignment, MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion, SizeOfHeaders, SizeOfImage, Subsystem, DllCharacteristics, SizeOfStackReserve, SizeOfStackCommit, Malware, SuspiciousImportFunctions, SectionsLenght, SectionMinEntropy, SectionMinRawsize, SectionMinSizeVirtual, SectionMaxPhysical, SectionMaxVirtual, SectionMaxPointerData, SectionMaxChar, DirectoryEntryImport, DirectoryImportSize, DirectoryEntryExport, ImageDirectoryEntryImport, ImageDirectoryEntryResource, ImageDirectoryEntrySecurity

This was based on going through each barplot and seeing if the values are at least a little bit spread.
Next feature extraction will be done via covar matrix to see if there are any patterns.
Machine                      Magic                          1.000000
Magic                        Machine                        1.000000
NumberOfSections             SectionsLength                 0.999977
SectionsLength               NumberOfSections               0.999977
SectionMinRawsize            SectionMinVirtualsize          0.999479
SectionMinVirtualsize        SectionMinRawsize              0.999479
MinorOperatingSystemVersion  MajorOperatingSystemVersion    0.903229
MajorOperatingSystemVersion  MinorOperatingSystemVersion    0.903229
Magic                        SizeOfOptionalHeader           0.901430
SizeOfOptionalHeader         Magic                          0.901430
                             Machine                        0.901430
Machine                      SizeOfOptionalHeader           0.901430
MinorOperatingSystemVersion  BaseOfCode                     0.886411
BaseOfCode                   MinorOperatingSystemVersion    0.886411
SectionMaxPointerData        AddressOfEntryPoint            0.882988
AddressOfEntryPoint          SectionMaxPointerData          0.882988
MajorImageVersion            MinorImageVersion              0.814190
MinorImageVersion            MajorImageVersion              0.814190
MajorOperatingSystemVersion  BaseOfCode                     0.772139
BaseOfCode                   MajorOperatingSystemVersion    0.772139
SectionMaxPhysical           ImageDirectoryEntryResource    0.741478
ImageDirectoryEntryResource  SectionMaxPhysical             0.741478
MajorImageVersion            MajorOperatingSystemVersion    0.666409
MajorOperatingSystemVersion  MajorImageVersion              0.666409
SizeOfCode                   SizeOfInitializedData          0.599257
SizeOfInitializedData        SizeOfCode                     0.599257
MajorImageVersion            MinorOperatingSystemVersion    0.593609
MinorOperatingSystemVersion  MajorImageVersion              0.593609
MajorImageVersion            BaseOfCode                     0.550572
BaseOfCode                   MajorImageVersion              0.550572
DirectoryEntryImportSize     DirectoryEntryImport           0.546222
DirectoryEntryImport         DirectoryEntryImportSize       0.546222
ImageDirectoryEntryImport    SectionMaxPhysical             0.510689
SectionMaxPhysical           ImageDirectoryEntryImport      0.510689
SectionMaxChar               SectionAlignment              -0.555643
SectionAlignment             SectionMaxChar                -0.555643
Malware                      MajorSubsystemVersion         -0.611621
MajorSubsystemVersion        Malware                       -0.611621