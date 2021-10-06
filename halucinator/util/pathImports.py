# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

import sys
sys.path.append("~/.ghidra/.$GHIDRA_VERSION/dev/jython_cachedir/python-src")
sys.path.append("~/.ghidra/.$GHIDRA_VERSION/osgi/felixcache")
sys.path.append("~/.ghidra/.$GHIDRA_VERSION/osgi/compiled-bundles")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/data/jython-2.7.2/Lib")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/lib/jython-standalone-2.7.2.jar/Lib")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/data/jython-2.7.2/Lib/site-packages")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Decompiler/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/VersionTracking/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FunctionID/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/DATA/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/8051/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/BytePatterns/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GnuDemangler/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/PIC/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/patch/")
sys.path.append("$GHIDRA_HOME/Ghidra/patch/jeromq-0.5.3-SNAPSHOT.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/DB/lib/DB.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Docking/lib/timingframework-1.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Docking/lib/Docking.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Docking/lib/javahelp-2.0.05.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/FileSystem/lib/FileSystem.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/FileSystem/lib/ganymed-ssh2-262.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/cglib-nodep-2.2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/guava-19.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/gson-2.8.6.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/commons-text-1.6.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/commons-collections4-4.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/log4j-api-2.12.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/jdom-legacy-1.1.3.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/log4j-core-2.12.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/commons-io-2.6.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/Generic.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/commons-lang3-3.9.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/jung-visualization-2.1.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/jung-api-2.1.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/jgrapht-core-1.4.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/Graph.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/jung-algorithms-2.1.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/jung-graph-impl-2.1.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Help/lib/Help.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Project/lib/Project.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Project/lib/commons-compress-1.19.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/msv-20050913.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/relaxngDatatype-20050913.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/antlr-runtime-3.5.2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/isorelax-20050913.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/antlr-3.5.2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/xsdlib-20050913.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Utility/lib/Utility.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Configurations/Public_Release/lib/Public_Release.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/Base.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/phidias-0.3.7.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/org.apache.felix.framework-6.0.3.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/slf4j-nop-1.7.25.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/biz.aQute.bndlib-5.1.2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/slf4j-api-1.7.25.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/BytePatterns/lib/BytePatterns.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/ByteViewer/lib/ByteViewer.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/DebugUtils/lib/DebugUtils.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Decompiler/lib/Decompiler.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/DecompilerDependent/lib/DecompilerDependent.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/dex-reader-api-2.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/sevenzipjbinding-16.02-2.01.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/baksmali-1.4.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/FileFormats.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/dex-ir-2.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/sevenzipjbinding-all-platforms-16.02-2.01.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/dexlib-1.4.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/asm-debug-all-4.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/dex-reader-2.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/util-1.4.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/AXMLPrinter2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/dex-translator-2.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FunctionGraph/lib/FunctionGraph.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FunctionGraphDecompilerExtension/lib/FunctionGraphDecompilerExtension.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FunctionID/lib/FunctionID.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GhidraServer/lib/GhidraServer.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GnuDemangler/lib/GnuDemangler.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphFunctionCalls/lib/GraphFunctionCalls.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/jgrapht-io-1.5.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/jungrapht-layout-1.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/GraphServices.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/jungrapht-visualization-1.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/data/jython-2.7.2/Lib")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/lib/jython-standalone-2.7.2.jar/Lib")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/data/jython-2.7.2/Lib/site-packages")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Decompiler/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/VersionTracking/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FunctionID/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/DATA/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/8051/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/BytePatterns/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GnuDemangler/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/PIC/ghidra_scripts")
sys.path.append("$GHIDRA_HOME/Ghidra/patch/")
sys.path.append("$GHIDRA_HOME/Ghidra/patch/jeromq-0.5.3-SNAPSHOT.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/DB/lib/DB.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Docking/lib/timingframework-1.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Docking/lib/Docking.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Docking/lib/javahelp-2.0.05.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/FileSystem/lib/FileSystem.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/FileSystem/lib/ganymed-ssh2-262.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/cglib-nodep-2.2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/guava-19.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/gson-2.8.6.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/commons-text-1.6.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/commons-collections4-4.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/log4j-api-2.12.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/jdom-legacy-1.1.3.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/log4j-core-2.12.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/commons-io-2.6.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/Generic.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Generic/lib/commons-lang3-3.9.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/jung-visualization-2.1.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/jung-api-2.1.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/jgrapht-core-1.4.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/Graph.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/jung-algorithms-2.1.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Graph/lib/jung-graph-impl-2.1.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Help/lib/Help.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Project/lib/Project.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Project/lib/commons-compress-1.19.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/msv-20050913.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/relaxngDatatype-20050913.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/antlr-runtime-3.5.2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/isorelax-20050913.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/antlr-3.5.2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/xsdlib-20050913.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Framework/Utility/lib/Utility.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Configurations/Public_Release/lib/Public_Release.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/Base.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/phidias-0.3.7.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/org.apache.felix.framework-6.0.3.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/slf4j-nop-1.7.25.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/biz.aQute.bndlib-5.1.2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Base/lib/slf4j-api-1.7.25.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/BytePatterns/lib/BytePatterns.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/ByteViewer/lib/ByteViewer.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/DebugUtils/lib/DebugUtils.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Decompiler/lib/Decompiler.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/DecompilerDependent/lib/DecompilerDependent.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/dex-reader-api-2.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/sevenzipjbinding-16.02-2.01.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/baksmali-1.4.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/FileFormats.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/dex-ir-2.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/sevenzipjbinding-all-platforms-16.02-2.01.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/dexlib-1.4.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/asm-debug-all-4.1.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/dex-reader-2.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/util-1.4.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/AXMLPrinter2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FileFormats/lib/dex-translator-2.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FunctionGraph/lib/FunctionGraph.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FunctionGraphDecompilerExtension/lib/FunctionGraphDecompilerExtension.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/FunctionID/lib/FunctionID.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GhidraServer/lib/GhidraServer.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GnuDemangler/lib/GnuDemangler.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphFunctionCalls/lib/GraphFunctionCalls.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/jgrapht-io-1.5.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/jungrapht-layout-1.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/GraphServices.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/jungrapht-visualization-1.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/jheaps-0.13.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/jgrapht-core-1.5.0.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/slf4j-nop-1.7.25.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/GraphServices/lib/slf4j-api-1.7.25.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/MicrosoftCodeAnalyzer/lib/MicrosoftCodeAnalyzer.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/MicrosoftDemangler/lib/MicrosoftDemangler.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/MicrosoftDmang/lib/MicrosoftDmang.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/PDB/lib/PDB.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/ProgramDiff/lib/ProgramDiff.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/ProgramGraph/lib/ProgramGraph.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/lib/Python.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/lib/jython-standalone-2.7.2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Recognizers/lib/Recognizers.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/SourceCodeLookup/lib/SourceCodeLookup.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/VersionTracking/lib/VersionTracking.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/68000/lib/68000.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/8051/lib/8051.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/AARCH64/lib/AARCH64.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/ARM/lib/ARM.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/Atmel/lib/Atmel.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/DATA/lib/DATA.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/Dalvik/lib/Dalvik.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/HCS12/lib/HCS12.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/JVM/lib/JVM.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/MIPS/lib/MIPS.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/PIC/lib/PIC.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/PowerPC/lib/PowerPC.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/RISCV/lib/RISCV.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/Sparc/lib/Sparc.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/SuperH4/lib/SuperH4.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/V850/lib/V850.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/tricore/lib/tricore.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/x86/lib/x86.jar]ramDiff.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/ProgramGraph/lib/ProgramGraph.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/lib/Python.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Python/lib/jython-standalone-2.7.2.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/Recognizers/lib/Recognizers.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/SourceCodeLookup/lib/SourceCodeLookup.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Features/VersionTracking/lib/VersionTracking.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/68000/lib/68000.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/8051/lib/8051.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/AARCH64/lib/AARCH64.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/ARM/lib/ARM.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/Atmel/lib/Atmel.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/DATA/lib/DATA.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/Dalvik/lib/Dalvik.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/HCS12/lib/HCS12.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/JVM/lib/JVM.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/MIPS/lib/MIPS.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/PIC/lib/PIC.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/PowerPC/lib/PowerPC.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/RISCV/lib/RISCV.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/Sparc/lib/Sparc.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/SuperH4/lib/SuperH4.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/V850/lib/V850.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/tricore/lib/tricore.jar")
sys.path.append("$GHIDRA_HOME/Ghidra/Processors/x86/lib/x86.jar]")