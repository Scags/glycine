import pefile
import sys
import ctypes
import struct
import capstone

from typing import Tuple

class IUnknown_vftable(ctypes.Structure):
	_fields_ = [
		("QueryInterface", ctypes.c_void_p),
		("AddRef", ctypes.c_void_p),
		("Release", ctypes.CFUNCTYPE(
					ctypes.c_ulong,        	# HRESULT
					ctypes.c_void_p, 		# |this|
		)),
	]

class IDiaDataSource_vftable(IUnknown_vftable):
	_fields_ = [
		("get_lastError", ctypes.c_void_p),
		("loadDataFromPdb", ctypes.CFUNCTYPE(
					ctypes.c_ulong,        	# HRESULT
					ctypes.c_void_p, 		# |this|
					ctypes.c_wchar_p,     	# LPCOLESTR
				)),
		("loadAndValidateDataFromPdb", ctypes.c_void_p),
		("loadDataForExe", ctypes.c_void_p),
		("loadDataFromIStream", ctypes.c_void_p),
		("openSession", ctypes.CFUNCTYPE(
					ctypes.c_ulong,        	# HRESULT
					ctypes.c_void_p, 		# |this|
					ctypes.c_void_p, 		# IDiaSession**
		)),
		("loadDataFromCodeViewInfo", ctypes.c_void_p),
		("loadDataFromMiscInfo", ctypes.c_void_p),
	]

class IDiaDataSource(ctypes.Structure):
	_fields_ = [
		("vftable", ctypes.POINTER(IDiaDataSource_vftable)),
	]


class IDiaSession_vftable(IUnknown_vftable):
	_fields_ = [
		("get_loadAddress", ctypes.c_void_p),
		("put_loadAddress", ctypes.c_void_p),
		("get_globalScope", ctypes.CFUNCTYPE(
					ctypes.c_ulong,        	# HRESULT
					ctypes.c_void_p, 		# |this|
					ctypes.c_void_p, 		# IDiaSymbol**
		)),
		("getEnumTables", ctypes.c_void_p),
		("getSymbolsByAddr", ctypes.c_void_p),
		("findChildren", ctypes.c_void_p),
		("findChildrenEx", ctypes.c_void_p),
		("findChildrenExByAddr", ctypes.c_void_p),
		("findChildrenExByVA", ctypes.c_void_p),
		("findChildrenExByRVA", ctypes.c_void_p),
		("findSymbolByAddr", ctypes.c_void_p),
		("findSymbolByRVA", ctypes.c_void_p),
		("findSymbolByVA", ctypes.c_void_p),
		("findSymbolByToken", ctypes.c_void_p),
		("symsAreEquiv", ctypes.c_void_p),
		("symbolById", ctypes.c_void_p),
		("findSymbolByRVAEx", ctypes.c_void_p),
		("findSymbolByVAEx", ctypes.c_void_p),
		("findFile", ctypes.c_void_p),
		("findFileById", ctypes.c_void_p),
		("findLines", ctypes.c_void_p),
		("findLinesByAddr", ctypes.c_void_p),
		("findLinesByRVA", ctypes.c_void_p),
		("findLinesByVA", ctypes.c_void_p),
		("findLinesByLinenum", ctypes.c_void_p),
		("findInjectedSource", ctypes.c_void_p),
		("getEnumDebugStreams", ctypes.c_void_p),
		("findInlineFramesByAddr", ctypes.c_void_p),
		("findInlineFramesByRVA", ctypes.c_void_p),
		("findInlineFramesByVA", ctypes.c_void_p),
		("findInlineeLines", ctypes.c_void_p),
		("findInlineeLinesByAddr", ctypes.c_void_p),
		("findInlineeLinesByRVA", ctypes.c_void_p),
		("findInlineeLinesByVA", ctypes.c_void_p),
		("findInlineeLinesByLinenum", ctypes.c_void_p),
		("findInlineesByName", ctypes.c_void_p),
		("findAcceleratorInlineeLinesByLinenum", ctypes.c_void_p),
		("findSymbolsForAcceleratorPointerTag", ctypes.c_void_p),
		("findSymbolsByRVAForAcceleratorPointerTag", ctypes.c_void_p),
		("findAcceleratorInlineesByName", ctypes.c_void_p),
		("addressForVA", ctypes.c_void_p),
		("addressForRVA", ctypes.c_void_p),
		("findILOffsetsByAddr", ctypes.c_void_p),
		("findILOffsetsByRVA", ctypes.c_void_p),
		("findILOffsetsByVA", ctypes.c_void_p),
		("findInputAssemblyFiles", ctypes.c_void_p),
		("findInputAssembly", ctypes.c_void_p),
		("findInputAssemblyById", ctypes.c_void_p),
		("getFuncMDTokenMapSize", ctypes.c_void_p),
		("getFuncMDTokenMap", ctypes.c_void_p),
		("getTypeMDTokenMapSize", ctypes.c_void_p),
		("getTypeMDTokenMap", ctypes.c_void_p),
		("getNumberOfFunctionFragments_VA", ctypes.c_void_p),
		("getNumberOfFunctionFragments_RVA", ctypes.c_void_p),
		("getFunctionFragments_VA", ctypes.c_void_p),
		("getFunctionFragments_RVA", ctypes.c_void_p),
		("getExports", ctypes.c_void_p),
		("getHeapAllocationSites", ctypes.c_void_p),
		("findInputAssemblyFile", ctypes.c_void_p),
	]


class IDiaSession(ctypes.Structure):
	_fields_ = [
		("vftable", ctypes.POINTER(IDiaSession_vftable)),
	]

class IDiaSymbol_vftable(IUnknown_vftable):
	_fields_ = [
		("get_symIndexId", ctypes.c_void_p),
		("get_symTag", ctypes.CFUNCTYPE(
					ctypes.c_ulong,        	# HRESULT
					ctypes.c_void_p, 		# |this|
					ctypes.POINTER(ctypes.c_ulong),   # SymTagEnum*
		)),
		("get_name", ctypes.CFUNCTYPE(
					ctypes.c_ulong,        				# HRESULT
					ctypes.c_void_p, 					# |this|
					ctypes.POINTER(ctypes.c_wchar_p),   # BSTR*
		)),
		("get_lexicalParent", ctypes.c_void_p),
		("get_classParent", ctypes.c_void_p),
		("get_type", ctypes.c_void_p),
		("get_dataKind", ctypes.c_void_p),
		("get_locationType", ctypes.c_void_p),
		("get_addressSection", ctypes.c_void_p),
		("get_addressOffset", ctypes.c_void_p),
		("get_relativeVirtualAddress", ctypes.CFUNCTYPE(
					ctypes.c_ulong,        				# HRESULT
					ctypes.c_void_p, 					# |this|
					ctypes.POINTER(ctypes.c_ulong),   # DWORD*
		)),
		("get_virtualAddress", ctypes.c_void_p),
		("get_registerId", ctypes.c_void_p),
		("get_offset", ctypes.c_void_p),
		("get_length", ctypes.c_void_p),
		("get_slot", ctypes.c_void_p),
		("get_volatileType", ctypes.c_void_p),
		("get_constType", ctypes.c_void_p),
		("get_unalignedType", ctypes.c_void_p),
		("get_access", ctypes.c_void_p),
		("get_libraryName", ctypes.c_void_p),
		("get_platform", ctypes.c_void_p),
		("get_language", ctypes.c_void_p),
		("get_editAndContinueEnabled", ctypes.c_void_p),
		("get_frontEndMajor", ctypes.c_void_p),
		("get_frontEndMinor", ctypes.c_void_p),
		("get_frontEndBuild", ctypes.c_void_p),
		("get_backEndMajor", ctypes.c_void_p),
		("get_backEndMinor", ctypes.c_void_p),
		("get_backEndBuild", ctypes.c_void_p),
		("get_sourceFileName", ctypes.c_void_p),
		("get_unused", ctypes.c_void_p),
		("get_thunkOrdinal", ctypes.c_void_p),
		("get_thisAdjust", ctypes.c_void_p),
		("get_virtualBaseOffset", ctypes.c_void_p),
		("get_virtual", ctypes.c_void_p),
		("get_intro", ctypes.c_void_p),
		("get_pure", ctypes.c_void_p),
		("get_callingConvention", ctypes.c_void_p),
		("get_value", ctypes.c_void_p),
		("get_baseType", ctypes.c_void_p),
		("get_token", ctypes.c_void_p),
		("get_timeStamp", ctypes.c_void_p),
		("get_guid", ctypes.c_void_p),
		("get_symbolsFileName", ctypes.c_void_p),
		("get_reference", ctypes.c_void_p),
		("get_count", ctypes.c_void_p),
		("get_bitPosition", ctypes.c_void_p),
		("get_arrayIndexType", ctypes.c_void_p),
		("get_packed", ctypes.c_void_p),
		("get_constructor", ctypes.c_void_p),
		("get_overloadedOperator", ctypes.c_void_p),
		("get_nested", ctypes.c_void_p),
		("get_hasNestedTypes", ctypes.c_void_p),
		("get_hasAssignmentOperator", ctypes.c_void_p),
		("get_hasCastOperator", ctypes.c_void_p),
		("get_scoped", ctypes.c_void_p),
		("get_virtualBaseClass", ctypes.c_void_p),
		("get_indirectVirtualBaseClass", ctypes.c_void_p),
		("get_virtualBasePointerOffset", ctypes.c_void_p),
		("get_virtualTableShape", ctypes.c_void_p),
		("get_lexicalParentId", ctypes.c_void_p),
		("get_classParentId", ctypes.c_void_p),
		("get_typeId", ctypes.c_void_p),
		("get_arrayIndexTypeId", ctypes.c_void_p),
		("get_virtualTableShapeId", ctypes.c_void_p),
		("get_code", ctypes.c_void_p),
		("get_function", ctypes.c_void_p),
		("get_managed", ctypes.c_void_p),
		("get_msil", ctypes.c_void_p),
		("get_virtualBaseDispIndex", ctypes.c_void_p),
		("get_undecoratedName", ctypes.CFUNCTYPE(
					ctypes.c_ulong,        				# HRESULT
					ctypes.c_void_p, 					# |this|
					ctypes.POINTER(ctypes.c_wchar_p),   # BSTR*
		)),
		("get_age", ctypes.c_void_p),
		("get_signature", ctypes.c_void_p),
		("get_compilerGenerated", ctypes.c_void_p),
		("get_addressTaken", ctypes.c_void_p),
		("get_rank", ctypes.c_void_p),
		("get_lowerBound", ctypes.c_void_p),
		("get_upperBound", ctypes.c_void_p),
		("get_lowerBoundId", ctypes.c_void_p),
		("get_upperBoundId", ctypes.c_void_p),
		("get_dataBytes", ctypes.c_void_p),
		("findChildren", ctypes.CFUNCTYPE(
					ctypes.c_ulong,        	# HRESULT
					ctypes.c_void_p, 		# |this|
					ctypes.c_ulong, 		# SymTagEnum
					ctypes.c_wchar_p,     	# LPCOLESTR
					ctypes.c_ulong, 		# NameSearchOptions
					ctypes.c_void_p, 		# IDiaEnumSymbols**
		)),
		("findChildrenEx", ctypes.c_void_p),
		("findChildrenExByAddr", ctypes.c_void_p),
		("findChildrenExByVA", ctypes.c_void_p),
		("findChildrenExByRVA", ctypes.c_void_p),
		("get_targetSection", ctypes.c_void_p),
		("get_targetOffset", ctypes.c_void_p),
		("get_targetRelativeVirtualAddress", ctypes.c_void_p),
		("get_targetVirtualAddress", ctypes.c_void_p),
		("get_machineType", ctypes.c_void_p),
		("get_oemId", ctypes.c_void_p),
		("get_oemSymbolId", ctypes.c_void_p),
		("get_types", ctypes.c_void_p),
		("get_typeIds", ctypes.c_void_p),
		("get_objectPointerType", ctypes.c_void_p),
		("get_udtKind", ctypes.c_void_p),
		("get_undecoratedNameEx", ctypes.c_void_p),
		("get_noReturn", ctypes.c_void_p),
		("get_customCallingConvention", ctypes.c_void_p),
		("get_noInline", ctypes.c_void_p),
		("get_optimizedCodeDebugInfo", ctypes.c_void_p),
		("get_notReached", ctypes.c_void_p),
		("get_interruptReturn", ctypes.c_void_p),
		("get_farReturn", ctypes.c_void_p),
		("get_isStatic", ctypes.c_void_p),
		("get_hasDebugInfo", ctypes.c_void_p),
		("get_isLTCG", ctypes.c_void_p),
		("get_isDataAligned", ctypes.c_void_p),
		("get_hasSecurityChecks", ctypes.c_void_p),
		("get_compilerName", ctypes.c_void_p),
		("get_hasAlloca", ctypes.c_void_p),
		("get_hasSetJump", ctypes.c_void_p),
		("get_hasLongJump", ctypes.c_void_p),
		("get_hasInlAsm", ctypes.c_void_p),
		("get_hasEH", ctypes.c_void_p),
		("get_hasSEH", ctypes.c_void_p),
		("get_hasEHa", ctypes.c_void_p),
		("get_isNaked", ctypes.c_void_p),
		("get_isAggregated", ctypes.c_void_p),
		("get_isSplitted", ctypes.c_void_p),
		("get_container", ctypes.c_void_p),
		("get_inlSpec", ctypes.c_void_p),
		("get_noStackOrdering", ctypes.c_void_p),
		("get_virtualBaseTableType", ctypes.c_void_p),
		("get_hasManagedCode", ctypes.c_void_p),
		("get_isHotpatchable", ctypes.c_void_p),
		("get_isCVTCIL", ctypes.c_void_p),
		("get_isMSILNetmodule", ctypes.c_void_p),
		("get_isCTypes", ctypes.c_void_p),
		("get_isStripped", ctypes.c_void_p),
		("get_frontEndQFE", ctypes.c_void_p),
		("get_backEndQFE", ctypes.c_void_p),
		("get_wasInlined", ctypes.c_void_p),
		("get_strictGSCheck", ctypes.c_void_p),
		("get_isCxxReturnUdt", ctypes.c_void_p),
		("get_isConstructorVirtualBase", ctypes.c_void_p),
		("get_RValueReference", ctypes.c_void_p),
		("get_unmodifiedType", ctypes.c_void_p),
		("get_framePointerPresent", ctypes.c_void_p),
		("get_isSafeBuffers", ctypes.c_void_p),
		("get_intrinsic", ctypes.c_void_p),
		("get_sealed", ctypes.c_void_p),
		("get_hfaFloat", ctypes.c_void_p),
		("get_hfaDouble", ctypes.c_void_p),
		("get_liveRangeStartAddressSection", ctypes.c_void_p),
		("get_liveRangeStartAddressOffset", ctypes.c_void_p),
		("get_liveRangeStartRelativeVirtualAddress", ctypes.c_void_p),
		("get_countLiveRanges", ctypes.c_void_p),
		("get_liveRangeLength", ctypes.c_void_p),
		("get_offsetInUdt", ctypes.c_void_p),
		("get_paramBasePointerRegisterId", ctypes.c_void_p),
		("get_localBasePointerRegisterId", ctypes.c_void_p),
		("get_isLocationControlFlowDependent", ctypes.c_void_p),
		("get_stride", ctypes.c_void_p),
		("get_numberOfRows", ctypes.c_void_p),
		("get_numberOfColumns", ctypes.c_void_p),
		("get_isMatrixRowMajor", ctypes.c_void_p),
		("get_numericProperties", ctypes.c_void_p),
		("get_modifierValues", ctypes.c_void_p),
		("get_isReturnValue", ctypes.c_void_p),
		("get_isOptimizedAway", ctypes.c_void_p),
		("get_builtInKind", ctypes.c_void_p),
		("get_registerType", ctypes.c_void_p),
		("get_baseDataSlot", ctypes.c_void_p),
		("get_baseDataOffset", ctypes.c_void_p),
		("get_textureSlot", ctypes.c_void_p),
		("get_samplerSlot", ctypes.c_void_p),
		("get_uavSlot", ctypes.c_void_p),
		("get_sizeInUdt", ctypes.c_void_p),
		("get_memorySpaceKind", ctypes.c_void_p),
		("get_unmodifiedTypeId", ctypes.c_void_p),
		("get_subTypeId", ctypes.c_void_p),
		("get_subType", ctypes.c_void_p),
		("get_numberOfModifiers", ctypes.c_void_p),
		("get_numberOfRegisterIndices", ctypes.c_void_p),
		("get_isHLSLData", ctypes.c_void_p),
		("get_isPointerToDataMember", ctypes.c_void_p),
		("get_isPointerToMemberFunction", ctypes.c_void_p),
		("get_isSingleInheritance", ctypes.c_void_p),
		("get_isMultipleInheritance", ctypes.c_void_p),
		("get_isVirtualInheritance", ctypes.c_void_p),
		("get_restrictedType", ctypes.c_void_p),
		("get_isPointerBasedOnSymbolValue", ctypes.c_void_p),
		("get_baseSymbol", ctypes.c_void_p),
		("get_baseSymbolId", ctypes.c_void_p),
		("get_objectFileName", ctypes.c_void_p),
		("get_isAcceleratorGroupSharedLocal", ctypes.c_void_p),
		("get_isAcceleratorPointerTagLiveRange", ctypes.c_void_p),
		("get_isAcceleratorStubFunction", ctypes.c_void_p),
		("get_numberOfAcceleratorPointerTags", ctypes.c_void_p),
		("get_isSdl", ctypes.c_void_p),
		("get_isWinRTPointer", ctypes.c_void_p),
		("get_isRefUdt", ctypes.c_void_p),
		("get_isValueUdt", ctypes.c_void_p),
		("get_isInterfaceUdt", ctypes.c_void_p),
		("findInlineFramesByAddr", ctypes.c_void_p),
		("findInlineFramesByRVA", ctypes.c_void_p),
		("findInlineFramesByVA", ctypes.c_void_p),
		("findInlineeLines", ctypes.c_void_p),
		("findInlineeLinesByAddr", ctypes.c_void_p),
		("findInlineeLinesByRVA", ctypes.c_void_p),
		("findInlineeLinesByVA", ctypes.c_void_p),
		("findSymbolsForAcceleratorPointerTag", ctypes.c_void_p),
		("findSymbolsByRVAForAcceleratorPointerTag", ctypes.c_void_p),
		("get_acceleratorPointerTags", ctypes.c_void_p),
		("getSrcLineOnTypeDefn", ctypes.c_void_p),
		("get_isPGO", ctypes.c_void_p),
		("get_hasValidPGOCounts", ctypes.c_void_p),
		("get_isOptimizedForSpeed", ctypes.c_void_p),
		("get_PGOEntryCount", ctypes.c_void_p),
		("get_PGOEdgeCount", ctypes.c_void_p),
		("get_PGODynamicInstructionCount", ctypes.c_void_p),
		("get_staticSize", ctypes.c_void_p),
		("get_finalLiveStaticSize", ctypes.c_void_p),
		("get_phaseName", ctypes.c_void_p),
		("get_hasControlFlowCheck", ctypes.c_void_p),
		("get_constantExport", ctypes.c_void_p),
		("get_dataExport", ctypes.c_void_p),
		("get_privateExport", ctypes.c_void_p),
		("get_noNameExport", ctypes.c_void_p),
		("get_exportHasExplicitlyAssignedOrdinal", ctypes.c_void_p),
		("get_exportIsForwarder", ctypes.c_void_p),
		("get_ordinal", ctypes.c_void_p),
		("get_frameSize", ctypes.c_void_p),
		("get_exceptionHandlerAddressSection", ctypes.c_void_p),
		("get_exceptionHandlerAddressOffset", ctypes.c_void_p),
		("get_exceptionHandlerRelativeVirtualAddress", ctypes.c_void_p),
		("get_exceptionHandlerVirtualAddress", ctypes.c_void_p),
		("findInputAssemblyFile", ctypes.c_void_p),
		("get_characteristics", ctypes.c_void_p),
		("get_coffGroup", ctypes.c_void_p),
		("get_bindID", ctypes.c_void_p),
		("get_bindSpace", ctypes.c_void_p),
		("get_bindSlot", ctypes.c_void_p),
	]

class IDiaSymbol(ctypes.Structure):
	_fields_ = [
		("vftable", ctypes.POINTER(IDiaSymbol_vftable)),
	]

class IDiaEnumSymbols_vftable(IUnknown_vftable):
	_fields_ = [
			("get__NewEnum", ctypes.c_void_p),
			("get_Count", ctypes.c_void_p),
			("Item", ctypes.c_void_p),
			("Next", ctypes.CFUNCTYPE(
					ctypes.c_ulong,        	# HRESULT
					ctypes.c_void_p, 		# |this|
					ctypes.c_ulong, 		# celt
					ctypes.c_void_p, 		# rgelt
					ctypes.c_void_p, 		# pceltFetched
			)),
			("Skip", ctypes.c_void_p),
			("Reset", ctypes.c_void_p),
			("Clone", ctypes.c_void_p),
		]

class IDiaEnumSymbols(ctypes.Structure):
	_fields_ = [
		("vftable", ctypes.POINTER(IDiaEnumSymbols_vftable)),
	]

# Pack to 1 (or I guess 4) byte
class function_info(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		("addresscrc", ctypes.c_uint32),
		("size", ctypes.c_uint32),
		("crc32", ctypes.c_uint32),
	]


CLSID_DiaSource = b"\x35\x61\x75\xE6\x65\x1E\x17\x4D\x85\x76\x61\x07\x61\x39\x8C\x3C"
IID_IDiaDataSource = b"\x5F\xBB\xF1\x79\x6E\xB6\xE5\x48\xB6\xA9\x15\x45\xC3\x23\xCA\x3D"
CLSCTX_INPROC_SERVER = 0x1
SymTagNull = 0
SymTagCompiland = 2
SymTagFunction = 5
SymTagPublicSymbol = 10

# Same implementation as glycine's
def crc32(data):
	crc = 0xFFFFFFFF
	for b in data:
		crc ^= b
		for _ in range(8):
			crc = ((crc >> 1) ^ 0xEDB88320) if (crc & 1) else crc >> 1
	return ~crc & 0xFFFFFFFF

def hresult(hr):
	return hr & 0xFFFFFFFF

def succeeded(hr):
	return hr >= 0

def failed(hr):
	return hr < 0

def get_invokes(globalscope):
	enumsymbols = ctypes.POINTER(IDiaEnumSymbols)()
	hr = globalscope.contents.vftable.contents.findChildren(globalscope, SymTagCompiland, None, 0, ctypes.byref(enumsymbols))
	if failed(hr):
		print(f"[!]Failed to find compiland -> {hresult(hr):#08x}")
		exit(1)
	
	functions = []
	# Now get compiland's children
	compiland = ctypes.POINTER(IDiaSymbol)()
	ccelt = ctypes.c_ulong(0)
	while succeeded(enumsymbols.contents.vftable.contents.Next(enumsymbols, 1, ctypes.byref(compiland), ctypes.byref(ccelt))) and ccelt.value == 1:
		enumchildren = ctypes.POINTER(IDiaEnumSymbols)()
		if succeeded(compiland.contents.vftable.contents.findChildren(compiland, SymTagNull, None, 0, ctypes.byref(enumchildren))):
			symbol = ctypes.POINTER(IDiaSymbol)()
			ccelt2 = ctypes.c_ulong(0)
			while succeeded(enumchildren.contents.vftable.contents.Next(enumchildren, 1, ctypes.byref(symbol), ctypes.byref(ccelt2))) and ccelt2.value == 1:
				symtag = ctypes.c_ulong(0)
				if failed(symbol.contents.vftable.contents.get_symTag(symbol, ctypes.byref(symtag))):
					continue

				if symtag.value == SymTagFunction:
					undname = ctypes.c_wchar_p()
					if symbol.contents.vftable.contents.get_undecoratedName(symbol, ctypes.byref(undname)) != 0:
						if symbol.contents.vftable.contents.get_name(symbol, ctypes.byref(undname)) != 0:
							continue
					
					if "glycine::Invoke" in str(undname.value):
						rva = ctypes.c_ulong(0)
						if succeeded(symbol.contents.vftable.contents.get_relativeVirtualAddress(symbol, ctypes.byref(rva))):
							functions.append(rva.value)

					ctypes.cdll.OleAut32.SysFreeString(undname)

				symbol.contents.vftable.contents.Release(symbol)
		compiland.contents.vftable.contents.Release(compiland)
	enumsymbols.contents.vftable.contents.Release(enumsymbols)

	return functions

def get_functions(globalscope):
	# glycine::functions is held in the publics
	enumsymbols = ctypes.POINTER(IDiaEnumSymbols)()
	hr = globalscope.contents.vftable.contents.findChildren(globalscope, SymTagPublicSymbol, None, 0, ctypes.byref(enumsymbols))
	if failed(hr):
		print(f"[!]Failed to find publics -> {hresult(hr):#08x}")
		exit(1)

	symbol = ctypes.POINTER(IDiaSymbol)()
	ccelt = ctypes.c_ulong(0)
	functions = 0
	while succeeded(enumsymbols.contents.vftable.contents.Next(enumsymbols, 1, ctypes.byref(symbol), ctypes.byref(ccelt))) and ccelt.value == 1:
		undname = ctypes.c_wchar_p()
		if symbol.contents.vftable.contents.get_undecoratedName(symbol, ctypes.byref(undname)) != 0:
			continue

		if "glycine::functions" in str(undname.value):
			rva = ctypes.c_ulong(0)
			if succeeded(symbol.contents.vftable.contents.get_relativeVirtualAddress(symbol, ctypes.byref(rva))):
				functions = rva.value
				break
		
		ctypes.cdll.OleAut32.SysFreeString(undname)
		symbol.contents.vftable.contents.Release(symbol)
	enumsymbols.contents.vftable.contents.Release(enumsymbols)

	return functions


def load_functions(pdbfile):
	ctypes.windll.ole32.CoInitialize(None)

	# Call CoCreateInstance
	datasource = ctypes.POINTER(IDiaDataSource)()
	diasource = ctypes.create_string_buffer(CLSID_DiaSource)
	iid = ctypes.create_string_buffer(IID_IDiaDataSource)
	hr = ctypes.windll.ole32.CoCreateInstance(
		diasource, None, CLSCTX_INPROC_SERVER, iid, ctypes.byref(datasource))

	if failed(hr):
		print(f"[!]Failed to create instance -> {hresult(hr):#08x}")
		print("Did you register msdia140.dll?")
		print("Go to C:\\Program Files\\Microsoft Visual Studio\\<version>\\Community\\DIA SDK\\bin\\amd64\\ "
		"in an admin command prompt and register your desired msdia140.dll with regsvr32.exe")
		exit(1)

	# Load the PDB
	wpdb = ctypes.create_unicode_buffer(pdbfile)
	hr = datasource.contents.vftable.contents.loadDataFromPdb(datasource, wpdb)
	if failed(hr):
		print(f"[!]Failed to load PDB -> {hresult(hr):#08x}")
		exit(1)
	
	# Open a session
	session = ctypes.POINTER(IDiaSession)()
	hr = datasource.contents.vftable.contents.openSession(datasource, ctypes.byref(session))
	if failed(hr):
		print(f"[!]Failed to open session -> {hresult(hr):#08x}")
		exit(1)

	# Get global scope
	globalscope = ctypes.POINTER(IDiaSymbol)()
	hr = session.contents.vftable.contents.get_globalScope(session, ctypes.byref(globalscope))

	if failed(hr):
		print(f"[!]Failed to get global scope -> {hresult(hr):#08x}")
		exit(1)

	# Get compiland
	invokes = get_invokes(globalscope)
	functions = get_functions(globalscope)
	globalscope.contents.vftable.contents.Release(globalscope)
	session.contents.vftable.contents.Release(session)

	return invokes, functions

def disasm_funkchunk(pe:pefile.PE, md, addr, chunksize = 0x100) -> bytes:
	data = bytes(pe.get_data(addr, chunksize))
	# Disassemble it with capstone
	sz = 0
	lastinsn = None
	for insn in md.disasm(data, 0):
		sz += insn.size
		# This is so stupid
		# So technically the chunksize is a lie because there's a (high) chance
		# that if a function exceeds chunksize in size, then the bytes won't
		# be disassembled correctly
		# So we just wing it and read chunksize - 10
		if chunksize - sz < 0xA:
			break

		# Another really stupid thing
		# There's not control flow analysis here, so if we hit a ret,
		# we just assume that's the end of the function
		# At least by this point hopefully a fair amount of the function will be encrypted
		if insn.mnemonic == "ret":
			break

		# Check for jumpouts at the end of a subroutine
		if lastinsn is not None and lastinsn.mnemonic == "jmp" and insn.mnemonic == "int3":
			sz -= 1
			break
		
		lastinsn = insn

	return data[:sz]

def patch_and_encrypt(pe:pefile.PE, invokes, functions):
	ffinfos = bytearray()
	# Get the base address of the pe
	base = pe.OPTIONAL_HEADER.ImageBase
	# First let's get each of the invokes and crc
	print("[+]Disassembling invocations")
	for rva in invokes:
		addr = base + rva

		# glycine::Invoke *shouldn't* be longer than this
		# Cipher shouldn't be inlined either
		maxlength = 0x100

		# Extract the bytes from the rva in the pe
		funcbytes = bytes(pe.get_data(rva, maxlength))

		# Disassemble it with capstone
		md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
		md.detail = True
		numcalls = 0
		calladdr = 0
		dryrun = False
		for insn in md.disasm(funcbytes, 0):
			# Terrible hack but this is how we check for GLYCINE_DRYRUN
			if insn.address == 0 and insn.bytes[0] == 0xE9:
				dryrun = True
				break

			# If we hit a call, inc
			if insn.mnemonic == "call":
				numcalls += 1
				# Second call is our target function
				if numcalls == 2:
					# Relative call
					if insn.bytes[0] == 0xE8:
						callrva = struct.unpack("<I", insn.bytes[1:])[0]
						nextaddr = rva + insn.address + insn.size
						calladdr = ctypes.c_uint32(nextaddr + ctypes.c_int32(callrva).value).value
					# Indirect call
					elif insn.bytes[0:2] == bytearray([0xFF, 0x15]):
						callrva = struct.unpack("<I", insn.bytes[2:])[0]
						nextaddr = rva + insn.address + insn.size
						calladdr = ctypes.c_uint32(nextaddr + ctypes.c_int32(callrva).value).value
					else:
						print(f"[!]Unknown call insn at {addr:#08x}")

					break
		if dryrun:
			print("[+]Dry run detected, quitting")
			exit(0)

		if calladdr == 0:
			print("[!]Failed to find actual function call in glycine::Invoke. What did you do?")
			exit(1)

		# Looking back at this I probably could've just parsed the function name out of the glycine::Invoke call name
		# and just gotten that rva from the PDB
		# Damn it...
		print(f"[+]Found glycine::Invoke at {addr:#08x}, calling {calladdr:#08x}")

		finfo = function_info()
		# We can firstly and quickly crc the address of the call
		finfo.addresscrc = crc32(struct.pack("<Q", calladdr + base))

		targetbytes = bytearray()
		# Sloth....
		while 1:
			chunksize = 0x100
			chunk = disasm_funkchunk(pe, md, calladdr + len(targetbytes), chunksize)
			# ... Chunk
			targetbytes.extend(chunk)
			if abs(len(chunk) - chunksize) > 0xA:
				break

		# Calculate the CRC32 of the function
		finfo.crc32 = crc32(targetbytes)
		finfo.size = len(targetbytes)

		# Now, encrypt the function bytes with a simple xor
		for i in range(len(targetbytes)):
			# Need to figure out how to get compatible with the C++ side somehow
			targetbytes[i] ^= 0x69

		# And patch it into the PE
		print(f"[+]Encrypting glycine invocation at {addr:#08x}")
		pe.set_bytes_at_rva(calladdr, bytes(targetbytes))

		ffinfos.extend(ctypes.string_at(ctypes.addressof(finfo), ctypes.sizeof(function_info)))

	print(f"[+]{len(ffinfos) // ctypes.sizeof(function_info)} invocations of glycine::Invoke found, beginning to patch into function info")

	# We need to get the sections that are at least Readable
	# and then see which of them has the most padding we can hijack
	sections = [s for s in pe.sections if s.Characteristics & 0x40000000]
	sections.sort(key=lambda s: s.SizeOfRawData - s.Misc_VirtualSize, reverse=True)
	targetsection = sections[0]

	# Now we pray that this is long enough
	sizeofinfos = len(ffinfos)
	alignedsize = targetsection.Misc_VirtualSize + (8 - (targetsection.Misc_VirtualSize % 8))
	bytesleft = targetsection.SizeOfRawData - alignedsize
	if sizeofinfos > bytesleft:
		print("[!]Not enough space to patch in glycine::function_info")
		print("Try messing with /ALIGN linker flag or try recompiling with random changes")
		print(f"Need {sizeofinfos} bytes, have {targetsection.SizeOfRawData - alignedsize} bytes")
		exit(1)

	# Now we patch in the function info	
	pe.set_bytes_at_rva(targetsection.VirtualAddress + alignedsize, bytes(ffinfos))

	# Lastly, set the functions struct pointer to point to this new location
	addrptr = pe.OPTIONAL_HEADER.ImageBase + targetsection.VirtualAddress + alignedsize
	pe.set_bytes_at_rva(functions, struct.pack("<Q", addrptr))

	# All done!
	print(f"[+]Patched in glycine::function_info at {addrptr:#08x} (rva {functions:#08x}, offset {pe.get_offset_from_rva(functions):#08x})")

def main():
	print("========== Running postbuild ==========")
	buildfile = sys.argv[1]
	pdbfile = sys.argv[2]


	pe = pefile.PE(buildfile)

	# ASLR
	if pe.OPTIONAL_HEADER.DllCharacteristics & 0x40:
		print("[!]TURN OFF ASLR!")
		exit(1)

	# Next, we try to find any cases of glycine::Invoke and map the function RVAs from the PDB to the PE
	# Unfortunately, we have to use the fricking COM and DIA API for this

	# "But John, why don't you just use pdbparser?"
	# Because pdbparser is unmaintained and broken in the latest version of construct
	# And Google is swarmed with these wierd ass protein database libraries and not an actual PDB parser
	# ... And I'm not writing my own
	invokes, functions = load_functions(pdbfile)

	# Now we patch in and encrypt the function info
	patch_and_encrypt(pe, invokes, functions)

	# Now save pe to file
	with open(buildfile, "wb") as f:
		f.write(pe.write())


if __name__ == '__main__':
	main()