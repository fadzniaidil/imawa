import os
import pefile
import hashlib
import math
import array
#path="/home/fadzni/Desktop/DoMP/Alternate Project/malware-classification/adwcleaner.exe"

def impExtraction(pe):
	imp =[]
	for i in pe.DIRECTORY_ENTRY_IMPORT:
		for j in i.imports:
			imp.append(str(j.name))
	return imp

def pure_import(path):
	pe = pefile.PE(path)
	xk = impExtraction(pe)
	point={}
		
	if "b'AVIMakeCompressedStream'" in xk:
		point["b'AVIMakeCompressedStream'"] = 1
	else:
		point["b'AVIMakeCompressedStream'"] = 0

	if "b'AbortDoc'" in xk:
		point["b'AbortDoc'"] = 1
	else:
		point["b'AbortDoc'"] = 0

	if "b'AbortPath'" in xk:
		point["b'AbortPath'"] = 1
	else:
		point["b'AbortPath'"] = 0

	if "b'AccessibleObjectFromWindow'" in xk:
		point["b'AccessibleObjectFromWindow'"] = 1
	else:
		point["b'AccessibleObjectFromWindow'"] = 0

	if "b'ActivateActCtx'" in xk:
		point["b'ActivateActCtx'"] = 1
	else:
		point["b'ActivateActCtx'"] = 0

	if "b'ActivateKeyboardLayout'" in xk:
		point["b'ActivateKeyboardLayout'"] = 1
	else:
		point["b'ActivateKeyboardLayout'"] = 0

	if "b'AddAccessAllowedAce'" in xk:
		point["b'AddAccessAllowedAce'"] = 1
	else:
		point["b'AddAccessAllowedAce'"] = 0

	if "b'AddAce'" in xk:
		point["b'AddAce'"] = 1
	else:
		point["b'AddAce'"] = 0

	if "b'AddAtomA'" in xk:
		point["b'AddAtomA'"] = 1
	else:
		point["b'AddAtomA'"] = 0

	if "b'AddAtomW'" in xk:
		point["b'AddAtomW'"] = 1
	else:
		point["b'AddAtomW'"] = 0

	if "b'AddFontMemResourceEx'" in xk:
		point["b'AddFontMemResourceEx'"] = 1
	else:
		point["b'AddFontMemResourceEx'"] = 0

	if "b'AddFontResourceA'" in xk:
		point["b'AddFontResourceA'"] = 1
	else:
		point["b'AddFontResourceA'"] = 0

	if "b'AddFontResourceW'" in xk:
		point["b'AddFontResourceW'"] = 1
	else:
		point["b'AddFontResourceW'"] = 0

	if "b'AddFontResourceExW'" in xk:
		point["b'AddFontResourceExW'"] = 1
	else:
		point["b'AddFontResourceExW'"] = 0

	if "b'AddRefActCtx'" in xk:
		point["b'AddRefActCtx'"] = 1
	else:
		point["b'AddRefActCtx'"] = 0

	if "b'AddVectoredExceptionHandler'" in xk:
		point["b'AddVectoredExceptionHandler'"] = 1
	else:
		point["b'AddVectoredExceptionHandler'"] = 0

	if "b'AdjustTokenGroups'" in xk:
		point["b'AdjustTokenGroups'"] = 1
	else:
		point["b'AdjustTokenGroups'"] = 0

	if "b'AdjustTokenPrivileges'" in xk:
		point["b'AdjustTokenPrivileges'"] = 1
	else:
		point["b'AdjustTokenPrivileges'"] = 0

	if "b'AdjustWindowRectEx'" in xk:
		point["b'AdjustWindowRectEx'"] = 1
	else:
		point["b'AdjustWindowRectEx'"] = 0

	if "b'AllocConsole'" in xk:
		point["b'AllocConsole'"] = 1
	else:
		point["b'AllocConsole'"] = 0

	if "b'AllocateAndInitializeSid'" in xk:
		point["b'AllocateAndInitializeSid'"] = 1
	else:
		point["b'AllocateAndInitializeSid'"] = 0

	if "b'AllocateLocallyUniqueId'" in xk:
		point["b'AllocateLocallyUniqueId'"] = 1
	else:
		point["b'AllocateLocallyUniqueId'"] = 0

	if "b'AllowSetForegroundWindow'" in xk:
		point["b'AllowSetForegroundWindow'"] = 1
	else:
		point["b'AllowSetForegroundWindow'"] = 0

	if "b'AlphaBlend'" in xk:
		point["b'AlphaBlend'"] = 1
	else:
		point["b'AlphaBlend'"] = 0

	if "b'AngleArc'" in xk:
		point["b'AngleArc'"] = 1
	else:
		point["b'AngleArc'"] = 0

	if "b'AnimatePalette'" in xk:
		point["b'AnimatePalette'"] = 1
	else:
		point["b'AnimatePalette'"] = 0

	if "b'AnyPopup'" in xk:
		point["b'AnyPopup'"] = 1
	else:
		point["b'AnyPopup'"] = 0

	if "b'AppendMenuA'" in xk:
		point["b'AppendMenuA'"] = 1
	else:
		point["b'AppendMenuA'"] = 0

	if "b'AppendMenuW'" in xk:
		point["b'AppendMenuW'"] = 1
	else:
		point["b'AppendMenuW'"] = 0

	if "b'Arc'" in xk:
		point["b'Arc'"] = 1
	else:
		point["b'Arc'"] = 0

	if "b'AreFileApisANSI'" in xk:
		point["b'AreFileApisANSI'"] = 1
	else:
		point["b'AreFileApisANSI'"] = 0

	if "b'AttachConsole'" in xk:
		point["b'AttachConsole'"] = 1
	else:
		point["b'AttachConsole'"] = 0

	if "b'AttachThreadInput'" in xk:
		point["b'AttachThreadInput'"] = 1
	else:
		point["b'AttachThreadInput'"] = 0

	if "b'AuthzFreeResourceManager'" in xk:
		point["b'AuthzFreeResourceManager'"] = 1
	else:
		point["b'AuthzFreeResourceManager'"] = 0

	if "b'AuthzInitializeContextFromSid'" in xk:
		point["b'AuthzInitializeContextFromSid'"] = 1
	else:
		point["b'AuthzInitializeContextFromSid'"] = 0

	if "b'BRUSHOBJ_pvAllocRbrush'" in xk:
		point["b'BRUSHOBJ_pvAllocRbrush'"] = 1
	else:
		point["b'BRUSHOBJ_pvAllocRbrush'"] = 0

	if "b'BackupRead'" in xk:
		point["b'BackupRead'"] = 1
	else:
		point["b'BackupRead'"] = 0

	if "b'Beep'" in xk:
		point["b'Beep'"] = 1
	else:
		point["b'Beep'"] = 0

	if "b'BeginDeferWindowPos'" in xk:
		point["b'BeginDeferWindowPos'"] = 1
	else:
		point["b'BeginDeferWindowPos'"] = 0

	if "b'BeginPaint'" in xk:
		point["b'BeginPaint'"] = 1
	else:
		point["b'BeginPaint'"] = 0

	if "b'BeginPath'" in xk:
		point["b'BeginPath'"] = 1
	else:
		point["b'BeginPath'"] = 0

	if "b'BeginUpdateResourceA'" in xk:
		point["b'BeginUpdateResourceA'"] = 1
	else:
		point["b'BeginUpdateResourceA'"] = 0

	if "b'BindIoCompletionCallback'" in xk:
		point["b'BindIoCompletionCallback'"] = 1
	else:
		point["b'BindIoCompletionCallback'"] = 0

	if "b'BitBlt'" in xk:
		point["b'BitBlt'"] = 1
	else:
		point["b'BitBlt'"] = 0

	if "b'BlockInput'" in xk:
		point["b'BlockInput'"] = 1
	else:
		point["b'BlockInput'"] = 0

	if "b'BringWindowToTop'" in xk:
		point["b'BringWindowToTop'"] = 1
	else:
		point["b'BringWindowToTop'"] = 0

	if "b'BroadcastSystemMessageA'" in xk:
		point["b'BroadcastSystemMessageA'"] = 1
	else:
		point["b'BroadcastSystemMessageA'"] = 0

	if "b'CLIPOBJ_ppoGetPath'" in xk:
		point["b'CLIPOBJ_ppoGetPath'"] = 1
	else:
		point["b'CLIPOBJ_ppoGetPath'"] = 0

	if "b'CLSIDFromProgID'" in xk:
		point["b'CLSIDFromProgID'"] = 1
	else:
		point["b'CLSIDFromProgID'"] = 0

	if "b'CLSIDFromString'" in xk:
		point["b'CLSIDFromString'"] = 1
	else:
		point["b'CLSIDFromString'"] = 0

	if "b'CallNamedPipeA'" in xk:
		point["b'CallNamedPipeA'"] = 1
	else:
		point["b'CallNamedPipeA'"] = 0

	if "b'CallNamedPipeW'" in xk:
		point["b'CallNamedPipeW'"] = 1
	else:
		point["b'CallNamedPipeW'"] = 0

	if "b'CallNextHookEx'" in xk:
		point["b'CallNextHookEx'"] = 1
	else:
		point["b'CallNextHookEx'"] = 0

	if "b'CallWindowProcA'" in xk:
		point["b'CallWindowProcA'"] = 1
	else:
		point["b'CallWindowProcA'"] = 0

	if "b'CallWindowProcW'" in xk:
		point["b'CallWindowProcW'"] = 1
	else:
		point["b'CallWindowProcW'"] = 0

	if "b'CancelDC'" in xk:
		point["b'CancelDC'"] = 1
	else:
		point["b'CancelDC'"] = 0

	if "b'CancelIoEx'" in xk:
		point["b'CancelIoEx'"] = 1
	else:
		point["b'CancelIoEx'"] = 0

	if "b'CertAddStoreToCollection'" in xk:
		point["b'CertAddStoreToCollection'"] = 1
	else:
		point["b'CertAddStoreToCollection'"] = 0

	if "b'CertAlgIdToOID'" in xk:
		point["b'CertAlgIdToOID'"] = 1
	else:
		point["b'CertAlgIdToOID'"] = 0

	if "b'CertCloseStore'" in xk:
		point["b'CertCloseStore'"] = 1
	else:
		point["b'CertCloseStore'"] = 0

	if "b'CertCompareCertificate'" in xk:
		point["b'CertCompareCertificate'"] = 1
	else:
		point["b'CertCompareCertificate'"] = 0

	if "b'CertControlStore'" in xk:
		point["b'CertControlStore'"] = 1
	else:
		point["b'CertControlStore'"] = 0

	if "b'CertCreateContext'" in xk:
		point["b'CertCreateContext'"] = 1
	else:
		point["b'CertCreateContext'"] = 0

	if "b'CertDuplicateCRLContext'" in xk:
		point["b'CertDuplicateCRLContext'"] = 1
	else:
		point["b'CertDuplicateCRLContext'"] = 0

	if "b'CertDuplicateStore'" in xk:
		point["b'CertDuplicateStore'"] = 1
	else:
		point["b'CertDuplicateStore'"] = 0

	if "b'CertFindAttribute'" in xk:
		point["b'CertFindAttribute'"] = 1
	else:
		point["b'CertFindAttribute'"] = 0

	if "b'CertFindCRLInStore'" in xk:
		point["b'CertFindCRLInStore'"] = 1
	else:
		point["b'CertFindCRLInStore'"] = 0

	if "b'CertFindCertificateInStore'" in xk:
		point["b'CertFindCertificateInStore'"] = 1
	else:
		point["b'CertFindCertificateInStore'"] = 0

	if "b'CertFindChaInStore'" in xk:
		point["b'CertFindChaInStore'"] = 1
	else:
		point["b'CertFindChaInStore'"] = 0

	if "b'CertFindExtension'" in xk:
		point["b'CertFindExtension'"] = 1
	else:
		point["b'CertFindExtension'"] = 0

	if "b'CertFreeCRLContext'" in xk:
		point["b'CertFreeCRLContext'"] = 1
	else:
		point["b'CertFreeCRLContext'"] = 0

	if "b'CertGetNameStringW'" in xk:
		point["b'CertGetNameStringW'"] = 1
	else:
		point["b'CertGetNameStringW'"] = 0

	if "b'CertNameToStrA'" in xk:
		point["b'CertNameToStrA'"] = 1
	else:
		point["b'CertNameToStrA'"] = 0

	if "b'CertOpenStore'" in xk:
		point["b'CertOpenStore'"] = 1
	else:
		point["b'CertOpenStore'"] = 0

	if "b'CertSaveStore'" in xk:
		point["b'CertSaveStore'"] = 1
	else:
		point["b'CertSaveStore'"] = 0

	if "b'ChangeDisplaySettingsW'" in xk:
		point["b'ChangeDisplaySettingsW'"] = 1
	else:
		point["b'ChangeDisplaySettingsW'"] = 0

	if "b'ChangeMenuA'" in xk:
		point["b'ChangeMenuA'"] = 1
	else:
		point["b'ChangeMenuA'"] = 0

	if "b'ChangeServiceConfigA'" in xk:
		point["b'ChangeServiceConfigA'"] = 1
	else:
		point["b'ChangeServiceConfigA'"] = 0

	if "b'ChangeServiceConfig2A'" in xk:
		point["b'ChangeServiceConfig2A'"] = 1
	else:
		point["b'ChangeServiceConfig2A'"] = 0

	if "b'ChangeServiceConfig2W'" in xk:
		point["b'ChangeServiceConfig2W'"] = 1
	else:
		point["b'ChangeServiceConfig2W'"] = 0

	if "b'ChangeTimerQueueTimer'" in xk:
		point["b'ChangeTimerQueueTimer'"] = 1
	else:
		point["b'ChangeTimerQueueTimer'"] = 0

	if "b'CharLowerA'" in xk:
		point["b'CharLowerA'"] = 1
	else:
		point["b'CharLowerA'"] = 0

	if "b'CharLowerW'" in xk:
		point["b'CharLowerW'"] = 1
	else:
		point["b'CharLowerW'"] = 0

	if "b'CharLowerBuffA'" in xk:
		point["b'CharLowerBuffA'"] = 1
	else:
		point["b'CharLowerBuffA'"] = 0

	if "b'CharLowerBuffW'" in xk:
		point["b'CharLowerBuffW'"] = 1
	else:
		point["b'CharLowerBuffW'"] = 0

	if "b'CharNextA'" in xk:
		point["b'CharNextA'"] = 1
	else:
		point["b'CharNextA'"] = 0

	if "b'CharNextW'" in xk:
		point["b'CharNextW'"] = 1
	else:
		point["b'CharNextW'"] = 0

	if "b'CharPrevA'" in xk:
		point["b'CharPrevA'"] = 1
	else:
		point["b'CharPrevA'"] = 0

	if "b'CharPrevW'" in xk:
		point["b'CharPrevW'"] = 1
	else:
		point["b'CharPrevW'"] = 0

	if "b'CharToOemA'" in xk:
		point["b'CharToOemA'"] = 1
	else:
		point["b'CharToOemA'"] = 0

	if "b'CharToOemW'" in xk:
		point["b'CharToOemW'"] = 1
	else:
		point["b'CharToOemW'"] = 0

	if "b'CharToOemBuffA'" in xk:
		point["b'CharToOemBuffA'"] = 1
	else:
		point["b'CharToOemBuffA'"] = 0

	if "b'CharToOemBuffW'" in xk:
		point["b'CharToOemBuffW'"] = 1
	else:
		point["b'CharToOemBuffW'"] = 0

	if "b'CharUpperA'" in xk:
		point["b'CharUpperA'"] = 1
	else:
		point["b'CharUpperA'"] = 0

	if "b'CharUpperW'" in xk:
		point["b'CharUpperW'"] = 1
	else:
		point["b'CharUpperW'"] = 0

	if "b'CharUpperBuffA'" in xk:
		point["b'CharUpperBuffA'"] = 1
	else:
		point["b'CharUpperBuffA'"] = 0

	if "b'CharUpperBuffW'" in xk:
		point["b'CharUpperBuffW'"] = 1
	else:
		point["b'CharUpperBuffW'"] = 0

	if "b'CheckADsError'" in xk:
		point["b'CheckADsError'"] = 1
	else:
		point["b'CheckADsError'"] = 0

	if "b'CheckDlgButton'" in xk:
		point["b'CheckDlgButton'"] = 1
	else:
		point["b'CheckDlgButton'"] = 0

	if "b'CheckEscapesW'" in xk:
		point["b'CheckEscapesW'"] = 1
	else:
		point["b'CheckEscapesW'"] = 0

	if "b'CheckMenuItem'" in xk:
		point["b'CheckMenuItem'"] = 1
	else:
		point["b'CheckMenuItem'"] = 0

	if "b'CheckMenuRadioItem'" in xk:
		point["b'CheckMenuRadioItem'"] = 1
	else:
		point["b'CheckMenuRadioItem'"] = 0

	if "b'CheckRadioButton'" in xk:
		point["b'CheckRadioButton'"] = 1
	else:
		point["b'CheckRadioButton'"] = 0

	if "b'CheckTokenMembership'" in xk:
		point["b'CheckTokenMembership'"] = 1
	else:
		point["b'CheckTokenMembership'"] = 0

	if "b'ChildWindowFromPoint'" in xk:
		point["b'ChildWindowFromPoint'"] = 1
	else:
		point["b'ChildWindowFromPoint'"] = 0

	if "b'ChooseColorA'" in xk:
		point["b'ChooseColorA'"] = 1
	else:
		point["b'ChooseColorA'"] = 0

	if "b'ChoosePixelFormat'" in xk:
		point["b'ChoosePixelFormat'"] = 1
	else:
		point["b'ChoosePixelFormat'"] = 0

	if "b'ClearCommBreak'" in xk:
		point["b'ClearCommBreak'"] = 1
	else:
		point["b'ClearCommBreak'"] = 0

	if "b'ClearEventLogW'" in xk:
		point["b'ClearEventLogW'"] = 1
	else:
		point["b'ClearEventLogW'"] = 0

	if "b'ClientToScreen'" in xk:
		point["b'ClientToScreen'"] = 1
	else:
		point["b'ClientToScreen'"] = 0

	if "b'CloseClipboard'" in xk:
		point["b'CloseClipboard'"] = 1
	else:
		point["b'CloseClipboard'"] = 0

	if "b'CloseClusterResource'" in xk:
		point["b'CloseClusterResource'"] = 1
	else:
		point["b'CloseClusterResource'"] = 0

	if "b'CloseDesktop'" in xk:
		point["b'CloseDesktop'"] = 1
	else:
		point["b'CloseDesktop'"] = 0

	if "b'CloseEnhMetaFile'" in xk:
		point["b'CloseEnhMetaFile'"] = 1
	else:
		point["b'CloseEnhMetaFile'"] = 0

	if "b'CloseFigure'" in xk:
		point["b'CloseFigure'"] = 1
	else:
		point["b'CloseFigure'"] = 0

	if "b'CloseHandle'" in xk:
		point["b'CloseHandle'"] = 1
	else:
		point["b'CloseHandle'"] = 0

	if "b'CloseMetaFile'" in xk:
		point["b'CloseMetaFile'"] = 1
	else:
		point["b'CloseMetaFile'"] = 0

	if "b'ClosePrinter'" in xk:
		point["b'ClosePrinter'"] = 1
	else:
		point["b'ClosePrinter'"] = 0

	if "b'CloseServiceHandle'" in xk:
		point["b'CloseServiceHandle'"] = 1
	else:
		point["b'CloseServiceHandle'"] = 0

	if "b'CloseThemeData'" in xk:
		point["b'CloseThemeData'"] = 1
	else:
		point["b'CloseThemeData'"] = 0

	if "b'CloseWindow'" in xk:
		point["b'CloseWindow'"] = 1
	else:
		point["b'CloseWindow'"] = 0

	if "b'CloseWindowStation'" in xk:
		point["b'CloseWindowStation'"] = 1
	else:
		point["b'CloseWindowStation'"] = 0

	if "b'ClusterGroupGetEnumCount'" in xk:
		point["b'ClusterGroupGetEnumCount'"] = 1
	else:
		point["b'ClusterGroupGetEnumCount'"] = 0

	if "b'ClusterOpenEnum'" in xk:
		point["b'ClusterOpenEnum'"] = 1
	else:
		point["b'ClusterOpenEnum'"] = 0

	if "b'ClusterRegDeleteValue'" in xk:
		point["b'ClusterRegDeleteValue'"] = 1
	else:
		point["b'ClusterRegDeleteValue'"] = 0

	if "b'ClusterRegEnumKey'" in xk:
		point["b'ClusterRegEnumKey'"] = 1
	else:
		point["b'ClusterRegEnumKey'"] = 0

	if "b'CoCreateActivity'" in xk:
		point["b'CoCreateActivity'"] = 1
	else:
		point["b'CoCreateActivity'"] = 0

	if "b'CoCreateGuid'" in xk:
		point["b'CoCreateGuid'"] = 1
	else:
		point["b'CoCreateGuid'"] = 0

	if "b'CoCreateInstance'" in xk:
		point["b'CoCreateInstance'"] = 1
	else:
		point["b'CoCreateInstance'"] = 0

	if "b'CoCreateInstanceEx'" in xk:
		point["b'CoCreateInstanceEx'"] = 1
	else:
		point["b'CoCreateInstanceEx'"] = 0

	if "b'CoDisconnectObject'" in xk:
		point["b'CoDisconnectObject'"] = 1
	else:
		point["b'CoDisconnectObject'"] = 0

	if "b'CoFileTimeNow'" in xk:
		point["b'CoFileTimeNow'"] = 1
	else:
		point["b'CoFileTimeNow'"] = 0

	if "b'CoFreeUnusedLibraries'" in xk:
		point["b'CoFreeUnusedLibraries'"] = 1
	else:
		point["b'CoFreeUnusedLibraries'"] = 0

	if "b'CoGetClassObject'" in xk:
		point["b'CoGetClassObject'"] = 1
	else:
		point["b'CoGetClassObject'"] = 0

	if "b'CoGetInstanceFromFile'" in xk:
		point["b'CoGetInstanceFromFile'"] = 1
	else:
		point["b'CoGetInstanceFromFile'"] = 0

	if "b'CoGetInterceptorFromTypeInfo'" in xk:
		point["b'CoGetInterceptorFromTypeInfo'"] = 1
	else:
		point["b'CoGetInterceptorFromTypeInfo'"] = 0

	if "b'CoGetObject'" in xk:
		point["b'CoGetObject'"] = 1
	else:
		point["b'CoGetObject'"] = 0

	if "b'CoInitialize'" in xk:
		point["b'CoInitialize'"] = 1
	else:
		point["b'CoInitialize'"] = 0

	if "b'CoInitializeEx'" in xk:
		point["b'CoInitializeEx'"] = 1
	else:
		point["b'CoInitializeEx'"] = 0

	if "b'CoInitializeSecurity'" in xk:
		point["b'CoInitializeSecurity'"] = 1
	else:
		point["b'CoInitializeSecurity'"] = 0

	if "b'CoLockObjectExternal'" in xk:
		point["b'CoLockObjectExternal'"] = 1
	else:
		point["b'CoLockObjectExternal'"] = 0

	if "b'CoRegisterMessageFilter'" in xk:
		point["b'CoRegisterMessageFilter'"] = 1
	else:
		point["b'CoRegisterMessageFilter'"] = 0

	if "b'CoResumeClassObjects'" in xk:
		point["b'CoResumeClassObjects'"] = 1
	else:
		point["b'CoResumeClassObjects'"] = 0

	if "b'CoRevokeClassObject'" in xk:
		point["b'CoRevokeClassObject'"] = 1
	else:
		point["b'CoRevokeClassObject'"] = 0

	if "b'CoSetProxyBlanket'" in xk:
		point["b'CoSetProxyBlanket'"] = 1
	else:
		point["b'CoSetProxyBlanket'"] = 0

	if "b'CoSuspendClassObjects'" in xk:
		point["b'CoSuspendClassObjects'"] = 1
	else:
		point["b'CoSuspendClassObjects'"] = 0

	if "b'CoTaskMemAlloc'" in xk:
		point["b'CoTaskMemAlloc'"] = 1
	else:
		point["b'CoTaskMemAlloc'"] = 0

	if "b'CoTaskMemFree'" in xk:
		point["b'CoTaskMemFree'"] = 1
	else:
		point["b'CoTaskMemFree'"] = 0

	if "b'CoTaskMemRealloc'" in xk:
		point["b'CoTaskMemRealloc'"] = 1
	else:
		point["b'CoTaskMemRealloc'"] = 0

	if "b'CoUninitialize'" in xk:
		point["b'CoUninitialize'"] = 1
	else:
		point["b'CoUninitialize'"] = 0

	if "b'ColorMatchToTarget'" in xk:
		point["b'ColorMatchToTarget'"] = 1
	else:
		point["b'ColorMatchToTarget'"] = 0

	if "b'CombineRgn'" in xk:
		point["b'CombineRgn'"] = 1
	else:
		point["b'CombineRgn'"] = 0

	if "b'CommConfigDialogW'" in xk:
		point["b'CommConfigDialogW'"] = 1
	else:
		point["b'CommConfigDialogW'"] = 0

	if "b'CommDlgExtendedError'" in xk:
		point["b'CommDlgExtendedError'"] = 1
	else:
		point["b'CommDlgExtendedError'"] = 0

	if "b'CommandLineToArgvW'" in xk:
		point["b'CommandLineToArgvW'"] = 1
	else:
		point["b'CommandLineToArgvW'"] = 0

	if "b'CompareFileTime'" in xk:
		point["b'CompareFileTime'"] = 1
	else:
		point["b'CompareFileTime'"] = 0

	if "b'CompareStringA'" in xk:
		point["b'CompareStringA'"] = 1
	else:
		point["b'CompareStringA'"] = 0

	if "b'CompareStringW'" in xk:
		point["b'CompareStringW'"] = 1
	else:
		point["b'CompareStringW'"] = 0

	if "b'CompareStringEx'" in xk:
		point["b'CompareStringEx'"] = 1
	else:
		point["b'CompareStringEx'"] = 0

	if "b'ConnectNamedPipe'" in xk:
		point["b'ConnectNamedPipe'"] = 1
	else:
		point["b'ConnectNamedPipe'"] = 0

	if "b'ConnectionRead'" in xk:
		point["b'ConnectionRead'"] = 1
	else:
		point["b'ConnectionRead'"] = 0

	if "b'ConnectionWrite'" in xk:
		point["b'ConnectionWrite'"] = 1
	else:
		point["b'ConnectionWrite'"] = 0

	if "b'ContinueDebugEvent'" in xk:
		point["b'ContinueDebugEvent'"] = 1
	else:
		point["b'ContinueDebugEvent'"] = 0

	if "b'ControlService'" in xk:
		point["b'ControlService'"] = 1
	else:
		point["b'ControlService'"] = 0

	if "b'ConvertDefaultLocale'" in xk:
		point["b'ConvertDefaultLocale'"] = 1
	else:
		point["b'ConvertDefaultLocale'"] = 0

	if "b'ConvertSidToStringSidW'" in xk:
		point["b'ConvertSidToStringSidW'"] = 1
	else:
		point["b'ConvertSidToStringSidW'"] = 0

	if "b'ConvertStringSecurityDescriptorToSecurityDescriptorW'" in xk:
		point["b'ConvertStringSecurityDescriptorToSecurityDescriptorW'"] = 1
	else:
		point["b'ConvertStringSecurityDescriptorToSecurityDescriptorW'"] = 0

	if "b'ConvertStringSidToSidW'" in xk:
		point["b'ConvertStringSidToSidW'"] = 1
	else:
		point["b'ConvertStringSidToSidW'"] = 0

	if "b'ConvertToAutoInheritPrivateObjectSecurity'" in xk:
		point["b'ConvertToAutoInheritPrivateObjectSecurity'"] = 1
	else:
		point["b'ConvertToAutoInheritPrivateObjectSecurity'"] = 0

	if "b'CopyAcceleratorTableA'" in xk:
		point["b'CopyAcceleratorTableA'"] = 1
	else:
		point["b'CopyAcceleratorTableA'"] = 0

	if "b'CopyAcceleratorTableW'" in xk:
		point["b'CopyAcceleratorTableW'"] = 1
	else:
		point["b'CopyAcceleratorTableW'"] = 0

	if "b'CopyEnhMetaFileA'" in xk:
		point["b'CopyEnhMetaFileA'"] = 1
	else:
		point["b'CopyEnhMetaFileA'"] = 0

	if "b'CopyFileA'" in xk:
		point["b'CopyFileA'"] = 1
	else:
		point["b'CopyFileA'"] = 0

	if "b'CopyFileW'" in xk:
		point["b'CopyFileW'"] = 1
	else:
		point["b'CopyFileW'"] = 0

	if "b'CopyFileExA'" in xk:
		point["b'CopyFileExA'"] = 1
	else:
		point["b'CopyFileExA'"] = 0

	if "b'CopyFileExW'" in xk:
		point["b'CopyFileExW'"] = 1
	else:
		point["b'CopyFileExW'"] = 0

	if "b'CopyIcon'" in xk:
		point["b'CopyIcon'"] = 1
	else:
		point["b'CopyIcon'"] = 0

	if "b'CopyImage'" in xk:
		point["b'CopyImage'"] = 1
	else:
		point["b'CopyImage'"] = 0

	if "b'CopyMetaFileA'" in xk:
		point["b'CopyMetaFileA'"] = 1
	else:
		point["b'CopyMetaFileA'"] = 0

	if "b'CopyMetaFileW'" in xk:
		point["b'CopyMetaFileW'"] = 1
	else:
		point["b'CopyMetaFileW'"] = 0

	if "b'CopyRect'" in xk:
		point["b'CopyRect'"] = 1
	else:
		point["b'CopyRect'"] = 0

	if "b'CopySid'" in xk:
		point["b'CopySid'"] = 1
	else:
		point["b'CopySid'"] = 0

	if "b'CountClipboardFormats'" in xk:
		point["b'CountClipboardFormats'"] = 1
	else:
		point["b'CountClipboardFormats'"] = 0

	if "b'CrackName'" in xk:
		point["b'CrackName'"] = 1
	else:
		point["b'CrackName'"] = 0

	if "b'CreateAcceleratorTableA'" in xk:
		point["b'CreateAcceleratorTableA'"] = 1
	else:
		point["b'CreateAcceleratorTableA'"] = 0

	if "b'CreateAcceleratorTableW'" in xk:
		point["b'CreateAcceleratorTableW'"] = 1
	else:
		point["b'CreateAcceleratorTableW'"] = 0

	if "b'CreateActCtxW'" in xk:
		point["b'CreateActCtxW'"] = 1
	else:
		point["b'CreateActCtxW'"] = 0

	if "b'CreateBitmap'" in xk:
		point["b'CreateBitmap'"] = 1
	else:
		point["b'CreateBitmap'"] = 0

	if "b'CreateBitmapIndirect'" in xk:
		point["b'CreateBitmapIndirect'"] = 1
	else:
		point["b'CreateBitmapIndirect'"] = 0

	if "b'CreateBrushIndirect'" in xk:
		point["b'CreateBrushIndirect'"] = 1
	else:
		point["b'CreateBrushIndirect'"] = 0

	if "b'CreateCompatibleBitmap'" in xk:
		point["b'CreateCompatibleBitmap'"] = 1
	else:
		point["b'CreateCompatibleBitmap'"] = 0

	if "b'CreateCompatibleDC'" in xk:
		point["b'CreateCompatibleDC'"] = 1
	else:
		point["b'CreateCompatibleDC'"] = 0

	if "b'CreateConsoleScreenBuffer'" in xk:
		point["b'CreateConsoleScreenBuffer'"] = 1
	else:
		point["b'CreateConsoleScreenBuffer'"] = 0

	if "b'CreateDCA'" in xk:
		point["b'CreateDCA'"] = 1
	else:
		point["b'CreateDCA'"] = 0

	if "b'CreateDCW'" in xk:
		point["b'CreateDCW'"] = 1
	else:
		point["b'CreateDCW'"] = 0

	if "b'CreateDIBPatternBrushPt'" in xk:
		point["b'CreateDIBPatternBrushPt'"] = 1
	else:
		point["b'CreateDIBPatternBrushPt'"] = 0

	if "b'CreateDIBSection'" in xk:
		point["b'CreateDIBSection'"] = 1
	else:
		point["b'CreateDIBSection'"] = 0

	if "b'CreateDIBitmap'" in xk:
		point["b'CreateDIBitmap'"] = 1
	else:
		point["b'CreateDIBitmap'"] = 0

	if "b'CreateDesktopA'" in xk:
		point["b'CreateDesktopA'"] = 1
	else:
		point["b'CreateDesktopA'"] = 0

	if "b'CreateDesktopW'" in xk:
		point["b'CreateDesktopW'"] = 1
	else:
		point["b'CreateDesktopW'"] = 0

	if "b'CreateDialogIndirectParamA'" in xk:
		point["b'CreateDialogIndirectParamA'"] = 1
	else:
		point["b'CreateDialogIndirectParamA'"] = 0

	if "b'CreateDialogIndirectParamW'" in xk:
		point["b'CreateDialogIndirectParamW'"] = 1
	else:
		point["b'CreateDialogIndirectParamW'"] = 0

	if "b'CreateDialogParamA'" in xk:
		point["b'CreateDialogParamA'"] = 1
	else:
		point["b'CreateDialogParamA'"] = 0

	if "b'CreateDialogParamW'" in xk:
		point["b'CreateDialogParamW'"] = 1
	else:
		point["b'CreateDialogParamW'"] = 0

	if "b'CreateDirectoryA'" in xk:
		point["b'CreateDirectoryA'"] = 1
	else:
		point["b'CreateDirectoryA'"] = 0

	if "b'CreateDirectoryW'" in xk:
		point["b'CreateDirectoryW'"] = 1
	else:
		point["b'CreateDirectoryW'"] = 0

	if "b'CreateDirectoryExA'" in xk:
		point["b'CreateDirectoryExA'"] = 1
	else:
		point["b'CreateDirectoryExA'"] = 0

	if "b'CreateDirectoryExW'" in xk:
		point["b'CreateDirectoryExW'"] = 1
	else:
		point["b'CreateDirectoryExW'"] = 0

	if "b'CreateEllipticRgn'" in xk:
		point["b'CreateEllipticRgn'"] = 1
	else:
		point["b'CreateEllipticRgn'"] = 0

	if "b'CreateEnvironmentBlock'" in xk:
		point["b'CreateEnvironmentBlock'"] = 1
	else:
		point["b'CreateEnvironmentBlock'"] = 0

	if "b'CreateEventA'" in xk:
		point["b'CreateEventA'"] = 1
	else:
		point["b'CreateEventA'"] = 0

	if "b'CreateEventW'" in xk:
		point["b'CreateEventW'"] = 1
	else:
		point["b'CreateEventW'"] = 0

	if "b'CreateFileA'" in xk:
		point["b'CreateFileA'"] = 1
	else:
		point["b'CreateFileA'"] = 0

	if "b'CreateFileW'" in xk:
		point["b'CreateFileW'"] = 1
	else:
		point["b'CreateFileW'"] = 0

	if "b'CreateFileMappingA'" in xk:
		point["b'CreateFileMappingA'"] = 1
	else:
		point["b'CreateFileMappingA'"] = 0

	if "b'CreateFileMappingW'" in xk:
		point["b'CreateFileMappingW'"] = 1
	else:
		point["b'CreateFileMappingW'"] = 0

	if "b'CreateFontA'" in xk:
		point["b'CreateFontA'"] = 1
	else:
		point["b'CreateFontA'"] = 0

	if "b'CreateFontW'" in xk:
		point["b'CreateFontW'"] = 1
	else:
		point["b'CreateFontW'"] = 0

	if "b'CreateFontIndirectA'" in xk:
		point["b'CreateFontIndirectA'"] = 1
	else:
		point["b'CreateFontIndirectA'"] = 0

	if "b'CreateFontIndirectW'" in xk:
		point["b'CreateFontIndirectW'"] = 1
	else:
		point["b'CreateFontIndirectW'"] = 0

	if "b'CreateHalftonePalette'" in xk:
		point["b'CreateHalftonePalette'"] = 1
	else:
		point["b'CreateHalftonePalette'"] = 0

	if "b'CreateHardLinkW'" in xk:
		point["b'CreateHardLinkW'"] = 1
	else:
		point["b'CreateHardLinkW'"] = 0

	if "b'CreateHatchBrush'" in xk:
		point["b'CreateHatchBrush'"] = 1
	else:
		point["b'CreateHatchBrush'"] = 0

	if "b'CreateICA'" in xk:
		point["b'CreateICA'"] = 1
	else:
		point["b'CreateICA'"] = 0

	if "b'CreateILockBytesOnHGlobal'" in xk:
		point["b'CreateILockBytesOnHGlobal'"] = 1
	else:
		point["b'CreateILockBytesOnHGlobal'"] = 0

	if "b'CreateIcon'" in xk:
		point["b'CreateIcon'"] = 1
	else:
		point["b'CreateIcon'"] = 0

	if "b'CreateIconFromResourceEx'" in xk:
		point["b'CreateIconFromResourceEx'"] = 1
	else:
		point["b'CreateIconFromResourceEx'"] = 0

	if "b'CreateIconIndirect'" in xk:
		point["b'CreateIconIndirect'"] = 1
	else:
		point["b'CreateIconIndirect'"] = 0

	if "b'CreateIoCompletionPort'" in xk:
		point["b'CreateIoCompletionPort'"] = 1
	else:
		point["b'CreateIoCompletionPort'"] = 0

	if "b'CreateJobObjectA'" in xk:
		point["b'CreateJobObjectA'"] = 1
	else:
		point["b'CreateJobObjectA'"] = 0

	if "b'CreateJobSet'" in xk:
		point["b'CreateJobSet'"] = 1
	else:
		point["b'CreateJobSet'"] = 0

	if "b'CreateMailslotW'" in xk:
		point["b'CreateMailslotW'"] = 1
	else:
		point["b'CreateMailslotW'"] = 0

	if "b'CreateMenu'" in xk:
		point["b'CreateMenu'"] = 1
	else:
		point["b'CreateMenu'"] = 0

	if "b'CreateMetaFileA'" in xk:
		point["b'CreateMetaFileA'"] = 1
	else:
		point["b'CreateMetaFileA'"] = 0

	if "b'CreateMutexA'" in xk:
		point["b'CreateMutexA'"] = 1
	else:
		point["b'CreateMutexA'"] = 0

	if "b'CreateMutexW'" in xk:
		point["b'CreateMutexW'"] = 1
	else:
		point["b'CreateMutexW'"] = 0

	if "b'CreateNamedPipeA'" in xk:
		point["b'CreateNamedPipeA'"] = 1
	else:
		point["b'CreateNamedPipeA'"] = 0

	if "b'CreateNamedPipeW'" in xk:
		point["b'CreateNamedPipeW'"] = 1
	else:
		point["b'CreateNamedPipeW'"] = 0

	if "b'CreatePalette'" in xk:
		point["b'CreatePalette'"] = 1
	else:
		point["b'CreatePalette'"] = 0

	if "b'CreatePatternBrush'" in xk:
		point["b'CreatePatternBrush'"] = 1
	else:
		point["b'CreatePatternBrush'"] = 0

	if "b'CreatePen'" in xk:
		point["b'CreatePen'"] = 1
	else:
		point["b'CreatePen'"] = 0

	if "b'CreatePenIndirect'" in xk:
		point["b'CreatePenIndirect'"] = 1
	else:
		point["b'CreatePenIndirect'"] = 0

	if "b'CreatePipe'" in xk:
		point["b'CreatePipe'"] = 1
	else:
		point["b'CreatePipe'"] = 0

	if "b'CreatePolygonRgn'" in xk:
		point["b'CreatePolygonRgn'"] = 1
	else:
		point["b'CreatePolygonRgn'"] = 0

	if "b'CreatePopupMenu'" in xk:
		point["b'CreatePopupMenu'"] = 1
	else:
		point["b'CreatePopupMenu'"] = 0

	if "b'CreateProcessA'" in xk:
		point["b'CreateProcessA'"] = 1
	else:
		point["b'CreateProcessA'"] = 0

	if "b'CreateProcessW'" in xk:
		point["b'CreateProcessW'"] = 1
	else:
		point["b'CreateProcessW'"] = 0

	if "b'CreateProcessAsUserA'" in xk:
		point["b'CreateProcessAsUserA'"] = 1
	else:
		point["b'CreateProcessAsUserA'"] = 0

	if "b'CreateProcessAsUserW'" in xk:
		point["b'CreateProcessAsUserW'"] = 1
	else:
		point["b'CreateProcessAsUserW'"] = 0

	if "b'CreateProcessWithLogonW'" in xk:
		point["b'CreateProcessWithLogonW'"] = 1
	else:
		point["b'CreateProcessWithLogonW'"] = 0

	if "b'CreatePropertySheetPageA'" in xk:
		point["b'CreatePropertySheetPageA'"] = 1
	else:
		point["b'CreatePropertySheetPageA'"] = 0

	if "b'CreatePropertySheetPageW'" in xk:
		point["b'CreatePropertySheetPageW'"] = 1
	else:
		point["b'CreatePropertySheetPageW'"] = 0

	if "b'CreateRectRgn'" in xk:
		point["b'CreateRectRgn'"] = 1
	else:
		point["b'CreateRectRgn'"] = 0

	if "b'CreateRectRgnIndirect'" in xk:
		point["b'CreateRectRgnIndirect'"] = 1
	else:
		point["b'CreateRectRgnIndirect'"] = 0

	if "b'CreateRemoteThread'" in xk:
		point["b'CreateRemoteThread'"] = 1
	else:
		point["b'CreateRemoteThread'"] = 0

	if "b'CreateRoundRectRgn'" in xk:
		point["b'CreateRoundRectRgn'"] = 1
	else:
		point["b'CreateRoundRectRgn'"] = 0

	if "b'CreateSemaphoreA'" in xk:
		point["b'CreateSemaphoreA'"] = 1
	else:
		point["b'CreateSemaphoreA'"] = 0

	if "b'CreateSemaphoreW'" in xk:
		point["b'CreateSemaphoreW'"] = 1
	else:
		point["b'CreateSemaphoreW'"] = 0

	if "b'CreateServiceA'" in xk:
		point["b'CreateServiceA'"] = 1
	else:
		point["b'CreateServiceA'"] = 0

	if "b'CreateServiceW'" in xk:
		point["b'CreateServiceW'"] = 1
	else:
		point["b'CreateServiceW'"] = 0

	if "b'CreateSolidBrush'" in xk:
		point["b'CreateSolidBrush'"] = 1
	else:
		point["b'CreateSolidBrush'"] = 0

	if "b'CreateStdAccessibleObject'" in xk:
		point["b'CreateStdAccessibleObject'"] = 1
	else:
		point["b'CreateStdAccessibleObject'"] = 0

	if "b'CreateStreamOnHGlobal'" in xk:
		point["b'CreateStreamOnHGlobal'"] = 1
	else:
		point["b'CreateStreamOnHGlobal'"] = 0

	if "b'CreateThread'" in xk:
		point["b'CreateThread'"] = 1
	else:
		point["b'CreateThread'"] = 0

	if "b'CreateTimerQueue'" in xk:
		point["b'CreateTimerQueue'"] = 1
	else:
		point["b'CreateTimerQueue'"] = 0

	if "b'CreateTimerQueueTimer'" in xk:
		point["b'CreateTimerQueueTimer'"] = 1
	else:
		point["b'CreateTimerQueueTimer'"] = 0

	if "b'CreateToolbar'" in xk:
		point["b'CreateToolbar'"] = 1
	else:
		point["b'CreateToolbar'"] = 0

	if "b'CreateToolbarEx'" in xk:
		point["b'CreateToolbarEx'"] = 1
	else:
		point["b'CreateToolbarEx'"] = 0

	if "b'CreateToolhelp32Snapshot'" in xk:
		point["b'CreateToolhelp32Snapshot'"] = 1
	else:
		point["b'CreateToolhelp32Snapshot'"] = 0

	if "b'CreateUrlCacheGroup'" in xk:
		point["b'CreateUrlCacheGroup'"] = 1
	else:
		point["b'CreateUrlCacheGroup'"] = 0

	if "b'CreateWaitableTimerA'" in xk:
		point["b'CreateWaitableTimerA'"] = 1
	else:
		point["b'CreateWaitableTimerA'"] = 0

	if "b'CreateWaitableTimerW'" in xk:
		point["b'CreateWaitableTimerW'"] = 1
	else:
		point["b'CreateWaitableTimerW'"] = 0

	if "b'CreateWellKnownSid'" in xk:
		point["b'CreateWellKnownSid'"] = 1
	else:
		point["b'CreateWellKnownSid'"] = 0

	if "b'CreateWindowExA'" in xk:
		point["b'CreateWindowExA'"] = 1
	else:
		point["b'CreateWindowExA'"] = 0

	if "b'CreateWindowExW'" in xk:
		point["b'CreateWindowExW'"] = 1
	else:
		point["b'CreateWindowExW'"] = 0

	if "b'CreateWindowStationA'" in xk:
		point["b'CreateWindowStationA'"] = 1
	else:
		point["b'CreateWindowStationA'"] = 0

	if "b'CreateWindowStationW'" in xk:
		point["b'CreateWindowStationW'"] = 1
	else:
		point["b'CreateWindowStationW'"] = 0

	if "b'CredEnumerateW'" in xk:
		point["b'CredEnumerateW'"] = 1
	else:
		point["b'CredEnumerateW'"] = 0

	if "b'CredFree'" in xk:
		point["b'CredFree'"] = 1
	else:
		point["b'CredFree'"] = 0

	if "b'CryptAcquireContextA'" in xk:
		point["b'CryptAcquireContextA'"] = 1
	else:
		point["b'CryptAcquireContextA'"] = 0

	if "b'CryptAcquireContextW'" in xk:
		point["b'CryptAcquireContextW'"] = 1
	else:
		point["b'CryptAcquireContextW'"] = 0

	if "b'CryptBinaryToStringA'" in xk:
		point["b'CryptBinaryToStringA'"] = 1
	else:
		point["b'CryptBinaryToStringA'"] = 0

	if "b'CryptBinaryToStringW'" in xk:
		point["b'CryptBinaryToStringW'"] = 1
	else:
		point["b'CryptBinaryToStringW'"] = 0

	if "b'CryptCreateHash'" in xk:
		point["b'CryptCreateHash'"] = 1
	else:
		point["b'CryptCreateHash'"] = 0

	if "b'CryptDecodeObjectEx'" in xk:
		point["b'CryptDecodeObjectEx'"] = 1
	else:
		point["b'CryptDecodeObjectEx'"] = 0

	if "b'CryptDecrypt'" in xk:
		point["b'CryptDecrypt'"] = 1
	else:
		point["b'CryptDecrypt'"] = 0

	if "b'CryptDeriveKey'" in xk:
		point["b'CryptDeriveKey'"] = 1
	else:
		point["b'CryptDeriveKey'"] = 0

	if "b'CryptDestroyHash'" in xk:
		point["b'CryptDestroyHash'"] = 1
	else:
		point["b'CryptDestroyHash'"] = 0

	if "b'CryptDestroyKey'" in xk:
		point["b'CryptDestroyKey'"] = 1
	else:
		point["b'CryptDestroyKey'"] = 0

	if "b'CryptEncrypt'" in xk:
		point["b'CryptEncrypt'"] = 1
	else:
		point["b'CryptEncrypt'"] = 0

	if "b'CryptEnumOIDInfo'" in xk:
		point["b'CryptEnumOIDInfo'"] = 1
	else:
		point["b'CryptEnumOIDInfo'"] = 0

	if "b'CryptExportKey'" in xk:
		point["b'CryptExportKey'"] = 1
	else:
		point["b'CryptExportKey'"] = 0

	if "b'CryptFindOIDInfo'" in xk:
		point["b'CryptFindOIDInfo'"] = 1
	else:
		point["b'CryptFindOIDInfo'"] = 0

	if "b'CryptFormatObject'" in xk:
		point["b'CryptFormatObject'"] = 1
	else:
		point["b'CryptFormatObject'"] = 0

	if "b'CryptGenKey'" in xk:
		point["b'CryptGenKey'"] = 1
	else:
		point["b'CryptGenKey'"] = 0

	if "b'CryptGenRandom'" in xk:
		point["b'CryptGenRandom'"] = 1
	else:
		point["b'CryptGenRandom'"] = 0

	if "b'CryptGetHashParam'" in xk:
		point["b'CryptGetHashParam'"] = 1
	else:
		point["b'CryptGetHashParam'"] = 0

	if "b'CryptGetKeyParam'" in xk:
		point["b'CryptGetKeyParam'"] = 1
	else:
		point["b'CryptGetKeyParam'"] = 0

	if "b'CryptHashData'" in xk:
		point["b'CryptHashData'"] = 1
	else:
		point["b'CryptHashData'"] = 0

	if "b'CryptHashToBeSigned'" in xk:
		point["b'CryptHashToBeSigned'"] = 1
	else:
		point["b'CryptHashToBeSigned'"] = 0

	if "b'CryptImportKey'" in xk:
		point["b'CryptImportKey'"] = 1
	else:
		point["b'CryptImportKey'"] = 0

	if "b'CryptMsgClose'" in xk:
		point["b'CryptMsgClose'"] = 1
	else:
		point["b'CryptMsgClose'"] = 0

	if "b'CryptMsgGetParam'" in xk:
		point["b'CryptMsgGetParam'"] = 1
	else:
		point["b'CryptMsgGetParam'"] = 0

	if "b'CryptProtectData'" in xk:
		point["b'CryptProtectData'"] = 1
	else:
		point["b'CryptProtectData'"] = 0

	if "b'CryptQueryObject'" in xk:
		point["b'CryptQueryObject'"] = 1
	else:
		point["b'CryptQueryObject'"] = 0

	if "b'CryptReleaseContext'" in xk:
		point["b'CryptReleaseContext'"] = 1
	else:
		point["b'CryptReleaseContext'"] = 0

	if "b'CryptSetKeyParam'" in xk:
		point["b'CryptSetKeyParam'"] = 1
	else:
		point["b'CryptSetKeyParam'"] = 0

	if "b'CryptSignHashW'" in xk:
		point["b'CryptSignHashW'"] = 1
	else:
		point["b'CryptSignHashW'"] = 0

	if "b'CryptStringToBinaryA'" in xk:
		point["b'CryptStringToBinaryA'"] = 1
	else:
		point["b'CryptStringToBinaryA'"] = 0

	if "b'CryptStringToBinaryW'" in xk:
		point["b'CryptStringToBinaryW'"] = 1
	else:
		point["b'CryptStringToBinaryW'"] = 0

	if "b'CryptUnprotectData'" in xk:
		point["b'CryptUnprotectData'"] = 1
	else:
		point["b'CryptUnprotectData'"] = 0

	if "b'DAD_DragEnterEx'" in xk:
		point["b'DAD_DragEnterEx'"] = 1
	else:
		point["b'DAD_DragEnterEx'"] = 0

	if "b'DPtoLP'" in xk:
		point["b'DPtoLP'"] = 1
	else:
		point["b'DPtoLP'"] = 0

	if "b'DcomChannelSetHResult'" in xk:
		point["b'DcomChannelSetHResult'"] = 1
	else:
		point["b'DcomChannelSetHResult'"] = 0

	if "b'DdeAccessData'" in xk:
		point["b'DdeAccessData'"] = 1
	else:
		point["b'DdeAccessData'"] = 0

	if "b'DdeCmpStringHandles'" in xk:
		point["b'DdeCmpStringHandles'"] = 1
	else:
		point["b'DdeCmpStringHandles'"] = 0

	if "b'DdeDisconnect'" in xk:
		point["b'DdeDisconnect'"] = 1
	else:
		point["b'DdeDisconnect'"] = 0

	if "b'DdeGetLastError'" in xk:
		point["b'DdeGetLastError'"] = 1
	else:
		point["b'DdeGetLastError'"] = 0

	if "b'DdeNameService'" in xk:
		point["b'DdeNameService'"] = 1
	else:
		point["b'DdeNameService'"] = 0

	if "b'DdeQueryStringW'" in xk:
		point["b'DdeQueryStringW'"] = 1
	else:
		point["b'DdeQueryStringW'"] = 0

	if "b'DeactivateActCtx'" in xk:
		point["b'DeactivateActCtx'"] = 1
	else:
		point["b'DeactivateActCtx'"] = 0

	if "b'DebugActiveProcess'" in xk:
		point["b'DebugActiveProcess'"] = 1
	else:
		point["b'DebugActiveProcess'"] = 0

	if "b'DebugActiveProcessStop'" in xk:
		point["b'DebugActiveProcessStop'"] = 1
	else:
		point["b'DebugActiveProcessStop'"] = 0

	if "b'DebugBreak'" in xk:
		point["b'DebugBreak'"] = 1
	else:
		point["b'DebugBreak'"] = 0

	if "b'DebugSetProcessKillOnExit'" in xk:
		point["b'DebugSetProcessKillOnExit'"] = 1
	else:
		point["b'DebugSetProcessKillOnExit'"] = 0

	if "b'DecodePointer'" in xk:
		point["b'DecodePointer'"] = 1
	else:
		point["b'DecodePointer'"] = 0

	if "b'DefDlgProcA'" in xk:
		point["b'DefDlgProcA'"] = 1
	else:
		point["b'DefDlgProcA'"] = 0

	if "b'DefDlgProcW'" in xk:
		point["b'DefDlgProcW'"] = 1
	else:
		point["b'DefDlgProcW'"] = 0

	if "b'DefFrameProcA'" in xk:
		point["b'DefFrameProcA'"] = 1
	else:
		point["b'DefFrameProcA'"] = 0

	if "b'DefFrameProcW'" in xk:
		point["b'DefFrameProcW'"] = 1
	else:
		point["b'DefFrameProcW'"] = 0

	if "b'DefMDIChildProcA'" in xk:
		point["b'DefMDIChildProcA'"] = 1
	else:
		point["b'DefMDIChildProcA'"] = 0

	if "b'DefMDIChildProcW'" in xk:
		point["b'DefMDIChildProcW'"] = 1
	else:
		point["b'DefMDIChildProcW'"] = 0

	if "b'DefWindowProcA'" in xk:
		point["b'DefWindowProcA'"] = 1
	else:
		point["b'DefWindowProcA'"] = 0

	if "b'DefWindowProcW'" in xk:
		point["b'DefWindowProcW'"] = 1
	else:
		point["b'DefWindowProcW'"] = 0

	if "b'DeferWindowPos'" in xk:
		point["b'DeferWindowPos'"] = 1
	else:
		point["b'DeferWindowPos'"] = 0

	if "b'DeleteAtom'" in xk:
		point["b'DeleteAtom'"] = 1
	else:
		point["b'DeleteAtom'"] = 0

	if "b'DeleteColorSpace'" in xk:
		point["b'DeleteColorSpace'"] = 1
	else:
		point["b'DeleteColorSpace'"] = 0

	if "b'DeleteCriticalSection'" in xk:
		point["b'DeleteCriticalSection'"] = 1
	else:
		point["b'DeleteCriticalSection'"] = 0

	if "b'DeleteDC'" in xk:
		point["b'DeleteDC'"] = 1
	else:
		point["b'DeleteDC'"] = 0

	if "b'DeleteEnhMetaFile'" in xk:
		point["b'DeleteEnhMetaFile'"] = 1
	else:
		point["b'DeleteEnhMetaFile'"] = 0

	if "b'DeleteFileA'" in xk:
		point["b'DeleteFileA'"] = 1
	else:
		point["b'DeleteFileA'"] = 0

	if "b'DeleteFileW'" in xk:
		point["b'DeleteFileW'"] = 1
	else:
		point["b'DeleteFileW'"] = 0

	if "b'DeleteMenu'" in xk:
		point["b'DeleteMenu'"] = 1
	else:
		point["b'DeleteMenu'"] = 0

	if "b'DeleteMetaFile'" in xk:
		point["b'DeleteMetaFile'"] = 1
	else:
		point["b'DeleteMetaFile'"] = 0

	if "b'DeleteObject'" in xk:
		point["b'DeleteObject'"] = 1
	else:
		point["b'DeleteObject'"] = 0

	if "b'DeleteService'" in xk:
		point["b'DeleteService'"] = 1
	else:
		point["b'DeleteService'"] = 0

	if "b'DeleteTimerQueueTimer'" in xk:
		point["b'DeleteTimerQueueTimer'"] = 1
	else:
		point["b'DeleteTimerQueueTimer'"] = 0

	if "b'DeleteUrlCacheEntryA'" in xk:
		point["b'DeleteUrlCacheEntryA'"] = 1
	else:
		point["b'DeleteUrlCacheEntryA'"] = 0

	if "b'DeleteUrlCacheEntryW'" in xk:
		point["b'DeleteUrlCacheEntryW'"] = 1
	else:
		point["b'DeleteUrlCacheEntryW'"] = 0

	if "b'DeregisterEventSource'" in xk:
		point["b'DeregisterEventSource'"] = 1
	else:
		point["b'DeregisterEventSource'"] = 0

	if "b'DeregisterShellHookWindow'" in xk:
		point["b'DeregisterShellHookWindow'"] = 1
	else:
		point["b'DeregisterShellHookWindow'"] = 0

	if "b'DescribePixelFormat'" in xk:
		point["b'DescribePixelFormat'"] = 1
	else:
		point["b'DescribePixelFormat'"] = 0

	if "b'DestroyAcceleratorTable'" in xk:
		point["b'DestroyAcceleratorTable'"] = 1
	else:
		point["b'DestroyAcceleratorTable'"] = 0

	if "b'DestroyCaret'" in xk:
		point["b'DestroyCaret'"] = 1
	else:
		point["b'DestroyCaret'"] = 0

	if "b'DestroyCursor'" in xk:
		point["b'DestroyCursor'"] = 1
	else:
		point["b'DestroyCursor'"] = 0

	if "b'DestroyEnvironmentBlock'" in xk:
		point["b'DestroyEnvironmentBlock'"] = 1
	else:
		point["b'DestroyEnvironmentBlock'"] = 0

	if "b'DestroyIcon'" in xk:
		point["b'DestroyIcon'"] = 1
	else:
		point["b'DestroyIcon'"] = 0

	if "b'DestroyMenu'" in xk:
		point["b'DestroyMenu'"] = 1
	else:
		point["b'DestroyMenu'"] = 0

	if "b'DestroyPropertySheetPage'" in xk:
		point["b'DestroyPropertySheetPage'"] = 1
	else:
		point["b'DestroyPropertySheetPage'"] = 0

	if "b'DestroyWindow'" in xk:
		point["b'DestroyWindow'"] = 1
	else:
		point["b'DestroyWindow'"] = 0

	if "b'DeviceIoControl'" in xk:
		point["b'DeviceIoControl'"] = 1
	else:
		point["b'DeviceIoControl'"] = 0

	if "b'DhcpAddServer'" in xk:
		point["b'DhcpAddServer'"] = 1
	else:
		point["b'DhcpAddServer'"] = 0

	if "b'DhcpCreateClass'" in xk:
		point["b'DhcpCreateClass'"] = 1
	else:
		point["b'DhcpCreateClass'"] = 0

	if "b'DhcpCreateOption'" in xk:
		point["b'DhcpCreateOption'"] = 1
	else:
		point["b'DhcpCreateOption'"] = 0

	if "b'DhcpCreateSubnet'" in xk:
		point["b'DhcpCreateSubnet'"] = 1
	else:
		point["b'DhcpCreateSubnet'"] = 0

	if "b'DhcpDeleteClass'" in xk:
		point["b'DhcpDeleteClass'"] = 1
	else:
		point["b'DhcpDeleteClass'"] = 0

	if "b'DhcpEnumSubnetClients'" in xk:
		point["b'DhcpEnumSubnetClients'"] = 1
	else:
		point["b'DhcpEnumSubnetClients'"] = 0

	if "b'DhcpEnumSubnets'" in xk:
		point["b'DhcpEnumSubnets'"] = 1
	else:
		point["b'DhcpEnumSubnets'"] = 0

	if "b'DhcpGetSubnetInfo'" in xk:
		point["b'DhcpGetSubnetInfo'"] = 1
	else:
		point["b'DhcpGetSubnetInfo'"] = 0

	if "b'DhcpRpcFreeMemory'" in xk:
		point["b'DhcpRpcFreeMemory'"] = 1
	else:
		point["b'DhcpRpcFreeMemory'"] = 0

	if "b'DialogBoxIndirectParamA'" in xk:
		point["b'DialogBoxIndirectParamA'"] = 1
	else:
		point["b'DialogBoxIndirectParamA'"] = 0

	if "b'DialogBoxIndirectParamW'" in xk:
		point["b'DialogBoxIndirectParamW'"] = 1
	else:
		point["b'DialogBoxIndirectParamW'"] = 0

	if "b'DialogBoxParamA'" in xk:
		point["b'DialogBoxParamA'"] = 1
	else:
		point["b'DialogBoxParamA'"] = 0

	if "b'DialogBoxParamW'" in xk:
		point["b'DialogBoxParamW'"] = 1
	else:
		point["b'DialogBoxParamW'"] = 0

	if "b'DisableThreadLibraryCalls'" in xk:
		point["b'DisableThreadLibraryCalls'"] = 1
	else:
		point["b'DisableThreadLibraryCalls'"] = 0

	if "b'DisconnectNamedPipe'" in xk:
		point["b'DisconnectNamedPipe'"] = 1
	else:
		point["b'DisconnectNamedPipe'"] = 0

	if "b'DispatchMessageA'" in xk:
		point["b'DispatchMessageA'"] = 1
	else:
		point["b'DispatchMessageA'"] = 0

	if "b'DispatchMessageW'" in xk:
		point["b'DispatchMessageW'"] = 1
	else:
		point["b'DispatchMessageW'"] = 0

	if "b'DlgDirListComboBoxA'" in xk:
		point["b'DlgDirListComboBoxA'"] = 1
	else:
		point["b'DlgDirListComboBoxA'"] = 0

	if "b'DllInitialize'" in xk:
		point["b'DllInitialize'"] = 1
	else:
		point["b'DllInitialize'"] = 0

	if "b'DllRegisterServer'" in xk:
		point["b'DllRegisterServer'"] = 1
	else:
		point["b'DllRegisterServer'"] = 0

	if "b'DnsFree'" in xk:
		point["b'DnsFree'"] = 1
	else:
		point["b'DnsFree'"] = 0

	if "b'DnsHostnameToComputerNameW'" in xk:
		point["b'DnsHostnameToComputerNameW'"] = 1
	else:
		point["b'DnsHostnameToComputerNameW'"] = 0

	if "b'DnsQuery_A'" in xk:
		point["b'DnsQuery_A'"] = 1
	else:
		point["b'DnsQuery_A'"] = 0

	if "b'DoDragDrop'" in xk:
		point["b'DoDragDrop'"] = 1
	else:
		point["b'DoDragDrop'"] = 0

	if "b'DoEnvironmentSubstA'" in xk:
		point["b'DoEnvironmentSubstA'"] = 1
	else:
		point["b'DoEnvironmentSubstA'"] = 0

	if "b'DoEnvironmentSubstW'" in xk:
		point["b'DoEnvironmentSubstW'"] = 1
	else:
		point["b'DoEnvironmentSubstW'"] = 0

	if "b'DocumentPropertiesA'" in xk:
		point["b'DocumentPropertiesA'"] = 1
	else:
		point["b'DocumentPropertiesA'"] = 0

	if "b'DocumentPropertiesW'" in xk:
		point["b'DocumentPropertiesW'"] = 1
	else:
		point["b'DocumentPropertiesW'"] = 0

	if "b'DosDateTimeToFileTime'" in xk:
		point["b'DosDateTimeToFileTime'"] = 1
	else:
		point["b'DosDateTimeToFileTime'"] = 0

	if "b'DragAcceptFiles'" in xk:
		point["b'DragAcceptFiles'"] = 1
	else:
		point["b'DragAcceptFiles'"] = 0

	if "b'DragFinish'" in xk:
		point["b'DragFinish'"] = 1
	else:
		point["b'DragFinish'"] = 0

	if "b'DragQueryFileA'" in xk:
		point["b'DragQueryFileA'"] = 1
	else:
		point["b'DragQueryFileA'"] = 0

	if "b'DragQueryFileW'" in xk:
		point["b'DragQueryFileW'"] = 1
	else:
		point["b'DragQueryFileW'"] = 0

	if "b'DragQueryFileAorW'" in xk:
		point["b'DragQueryFileAorW'"] = 1
	else:
		point["b'DragQueryFileAorW'"] = 0

	if "b'DragQueryPoint'" in xk:
		point["b'DragQueryPoint'"] = 1
	else:
		point["b'DragQueryPoint'"] = 0

	if "b'DrawAnimatedRects'" in xk:
		point["b'DrawAnimatedRects'"] = 1
	else:
		point["b'DrawAnimatedRects'"] = 0

	if "b'DrawEdge'" in xk:
		point["b'DrawEdge'"] = 1
	else:
		point["b'DrawEdge'"] = 0

	if "b'DrawFocusRect'" in xk:
		point["b'DrawFocusRect'"] = 1
	else:
		point["b'DrawFocusRect'"] = 0

	if "b'DrawFrameControl'" in xk:
		point["b'DrawFrameControl'"] = 1
	else:
		point["b'DrawFrameControl'"] = 0

	if "b'DrawIcon'" in xk:
		point["b'DrawIcon'"] = 1
	else:
		point["b'DrawIcon'"] = 0

	if "b'DrawIconEx'" in xk:
		point["b'DrawIconEx'"] = 1
	else:
		point["b'DrawIconEx'"] = 0

	if "b'DrawMenuBar'" in xk:
		point["b'DrawMenuBar'"] = 1
	else:
		point["b'DrawMenuBar'"] = 0

	if "b'DrawStateA'" in xk:
		point["b'DrawStateA'"] = 1
	else:
		point["b'DrawStateA'"] = 0

	if "b'DrawStateW'" in xk:
		point["b'DrawStateW'"] = 1
	else:
		point["b'DrawStateW'"] = 0

	if "b'DrawTextA'" in xk:
		point["b'DrawTextA'"] = 1
	else:
		point["b'DrawTextA'"] = 0

	if "b'DrawTextW'" in xk:
		point["b'DrawTextW'"] = 1
	else:
		point["b'DrawTextW'"] = 0

	if "b'DrawTextExA'" in xk:
		point["b'DrawTextExA'"] = 1
	else:
		point["b'DrawTextExA'"] = 0

	if "b'DrawTextExW'" in xk:
		point["b'DrawTextExW'"] = 1
	else:
		point["b'DrawTextExW'"] = 0

	if "b'DrawThemeBackground'" in xk:
		point["b'DrawThemeBackground'"] = 1
	else:
		point["b'DrawThemeBackground'"] = 0

	if "b'DrawThemeEdge'" in xk:
		point["b'DrawThemeEdge'"] = 1
	else:
		point["b'DrawThemeEdge'"] = 0

	if "b'DrawThemeParentBackground'" in xk:
		point["b'DrawThemeParentBackground'"] = 1
	else:
		point["b'DrawThemeParentBackground'"] = 0

	if "b'DrawThemeText'" in xk:
		point["b'DrawThemeText'"] = 1
	else:
		point["b'DrawThemeText'"] = 0

	if "b'DsGetDcNameA'" in xk:
		point["b'DsGetDcNameA'"] = 1
	else:
		point["b'DsGetDcNameA'"] = 0

	if "b'DuplicateHandle'" in xk:
		point["b'DuplicateHandle'"] = 1
	else:
		point["b'DuplicateHandle'"] = 0

	if "b'DuplicateIcon'" in xk:
		point["b'DuplicateIcon'"] = 1
	else:
		point["b'DuplicateIcon'"] = 0

	if "b'DuplicateToken'" in xk:
		point["b'DuplicateToken'"] = 1
	else:
		point["b'DuplicateToken'"] = 0

	if "b'DuplicateTokenEx'" in xk:
		point["b'DuplicateTokenEx'"] = 1
	else:
		point["b'DuplicateTokenEx'"] = 0

	if "b'Ellipse'" in xk:
		point["b'Ellipse'"] = 1
	else:
		point["b'Ellipse'"] = 0

	if "b'EmptyClipboard'" in xk:
		point["b'EmptyClipboard'"] = 1
	else:
		point["b'EmptyClipboard'"] = 0

	if "b'EnableMenuItem'" in xk:
		point["b'EnableMenuItem'"] = 1
	else:
		point["b'EnableMenuItem'"] = 0

	if "b'EnableScrollBar'" in xk:
		point["b'EnableScrollBar'"] = 1
	else:
		point["b'EnableScrollBar'"] = 0

	if "b'EnableWindow'" in xk:
		point["b'EnableWindow'"] = 1
	else:
		point["b'EnableWindow'"] = 0

	if "b'EncodePointer'" in xk:
		point["b'EncodePointer'"] = 1
	else:
		point["b'EncodePointer'"] = 0

	if "b'EncryptFileW'" in xk:
		point["b'EncryptFileW'"] = 1
	else:
		point["b'EncryptFileW'"] = 0

	if "b'EndDeferWindowPos'" in xk:
		point["b'EndDeferWindowPos'"] = 1
	else:
		point["b'EndDeferWindowPos'"] = 0

	if "b'EndDialog'" in xk:
		point["b'EndDialog'"] = 1
	else:
		point["b'EndDialog'"] = 0

	if "b'EndDoc'" in xk:
		point["b'EndDoc'"] = 1
	else:
		point["b'EndDoc'"] = 0

	if "b'EndMenu'" in xk:
		point["b'EndMenu'"] = 1
	else:
		point["b'EndMenu'"] = 0

	if "b'EndPage'" in xk:
		point["b'EndPage'"] = 1
	else:
		point["b'EndPage'"] = 0

	if "b'EndPaint'" in xk:
		point["b'EndPaint'"] = 1
	else:
		point["b'EndPaint'"] = 0

	if "b'EndPath'" in xk:
		point["b'EndPath'"] = 1
	else:
		point["b'EndPath'"] = 0

	if "b'EndUpdateResourceA'" in xk:
		point["b'EndUpdateResourceA'"] = 1
	else:
		point["b'EndUpdateResourceA'"] = 0

	if "b'EndUpdateResourceW'" in xk:
		point["b'EndUpdateResourceW'"] = 1
	else:
		point["b'EndUpdateResourceW'"] = 0

	if "b'EngCreateBitmap'" in xk:
		point["b'EngCreateBitmap'"] = 1
	else:
		point["b'EngCreateBitmap'"] = 0

	if "b'EngCreateClip'" in xk:
		point["b'EngCreateClip'"] = 1
	else:
		point["b'EngCreateClip'"] = 0

	if "b'EngDeletePath'" in xk:
		point["b'EngDeletePath'"] = 1
	else:
		point["b'EngDeletePath'"] = 0

	if "b'EngFreeModule'" in xk:
		point["b'EngFreeModule'"] = 1
	else:
		point["b'EngFreeModule'"] = 0

	if "b'EngGradientFill'" in xk:
		point["b'EngGradientFill'"] = 1
	else:
		point["b'EngGradientFill'"] = 0

	if "b'EngStretchBltROP'" in xk:
		point["b'EngStretchBltROP'"] = 1
	else:
		point["b'EngStretchBltROP'"] = 0

	if "b'EngTextOut'" in xk:
		point["b'EngTextOut'"] = 1
	else:
		point["b'EngTextOut'"] = 0

	if "b'EnterCriticalSection'" in xk:
		point["b'EnterCriticalSection'"] = 1
	else:
		point["b'EnterCriticalSection'"] = 0

	if "b'EnumCalendarInfoA'" in xk:
		point["b'EnumCalendarInfoA'"] = 1
	else:
		point["b'EnumCalendarInfoA'"] = 0

	if "b'EnumCalendarInfoW'" in xk:
		point["b'EnumCalendarInfoW'"] = 1
	else:
		point["b'EnumCalendarInfoW'"] = 0

	if "b'EnumChildWindows'" in xk:
		point["b'EnumChildWindows'"] = 1
	else:
		point["b'EnumChildWindows'"] = 0

	if "b'EnumClipboardFormats'" in xk:
		point["b'EnumClipboardFormats'"] = 1
	else:
		point["b'EnumClipboardFormats'"] = 0

	if "b'EnumDateFormatsA'" in xk:
		point["b'EnumDateFormatsA'"] = 1
	else:
		point["b'EnumDateFormatsA'"] = 0

	if "b'EnumDateFormatsW'" in xk:
		point["b'EnumDateFormatsW'"] = 1
	else:
		point["b'EnumDateFormatsW'"] = 0

	if "b'EnumDesktopWindows'" in xk:
		point["b'EnumDesktopWindows'"] = 1
	else:
		point["b'EnumDesktopWindows'"] = 0

	if "b'EnumDesktopsA'" in xk:
		point["b'EnumDesktopsA'"] = 1
	else:
		point["b'EnumDesktopsA'"] = 0

	if "b'EnumDisplayDevicesA'" in xk:
		point["b'EnumDisplayDevicesA'"] = 1
	else:
		point["b'EnumDisplayDevicesA'"] = 0

	if "b'EnumDisplayMonitors'" in xk:
		point["b'EnumDisplayMonitors'"] = 1
	else:
		point["b'EnumDisplayMonitors'"] = 0

	if "b'EnumDisplaySettingsA'" in xk:
		point["b'EnumDisplaySettingsA'"] = 1
	else:
		point["b'EnumDisplaySettingsA'"] = 0

	if "b'EnumFontFamiliesA'" in xk:
		point["b'EnumFontFamiliesA'"] = 1
	else:
		point["b'EnumFontFamiliesA'"] = 0

	if "b'EnumFontFamiliesW'" in xk:
		point["b'EnumFontFamiliesW'"] = 1
	else:
		point["b'EnumFontFamiliesW'"] = 0

	if "b'EnumFontFamiliesExA'" in xk:
		point["b'EnumFontFamiliesExA'"] = 1
	else:
		point["b'EnumFontFamiliesExA'"] = 0

	if "b'EnumFontFamiliesExW'" in xk:
		point["b'EnumFontFamiliesExW'"] = 1
	else:
		point["b'EnumFontFamiliesExW'"] = 0

	if "b'EnumFontsA'" in xk:
		point["b'EnumFontsA'"] = 1
	else:
		point["b'EnumFontsA'"] = 0

	if "b'EnumFontsW'" in xk:
		point["b'EnumFontsW'"] = 1
	else:
		point["b'EnumFontsW'"] = 0

	if "b'EnumLanguageGroupLocalesA'" in xk:
		point["b'EnumLanguageGroupLocalesA'"] = 1
	else:
		point["b'EnumLanguageGroupLocalesA'"] = 0

	if "b'EnumProcessModules'" in xk:
		point["b'EnumProcessModules'"] = 1
	else:
		point["b'EnumProcessModules'"] = 0

	if "b'EnumProcesses'" in xk:
		point["b'EnumProcesses'"] = 1
	else:
		point["b'EnumProcesses'"] = 0

	if "b'EnumResourceLanguagesA'" in xk:
		point["b'EnumResourceLanguagesA'"] = 1
	else:
		point["b'EnumResourceLanguagesA'"] = 0

	if "b'EnumResourceLanguagesW'" in xk:
		point["b'EnumResourceLanguagesW'"] = 1
	else:
		point["b'EnumResourceLanguagesW'"] = 0

	if "b'EnumResourceNamesA'" in xk:
		point["b'EnumResourceNamesA'"] = 1
	else:
		point["b'EnumResourceNamesA'"] = 0

	if "b'EnumResourceNamesW'" in xk:
		point["b'EnumResourceNamesW'"] = 1
	else:
		point["b'EnumResourceNamesW'"] = 0

	if "b'EnumServicesStatusA'" in xk:
		point["b'EnumServicesStatusA'"] = 1
	else:
		point["b'EnumServicesStatusA'"] = 0

	if "b'EnumServicesStatusW'" in xk:
		point["b'EnumServicesStatusW'"] = 1
	else:
		point["b'EnumServicesStatusW'"] = 0

	if "b'EnumSystemLocalesA'" in xk:
		point["b'EnumSystemLocalesA'"] = 1
	else:
		point["b'EnumSystemLocalesA'"] = 0

	if "b'EnumSystemLocalesW'" in xk:
		point["b'EnumSystemLocalesW'"] = 1
	else:
		point["b'EnumSystemLocalesW'"] = 0

	if "b'EnumSystemLocalesEx'" in xk:
		point["b'EnumSystemLocalesEx'"] = 1
	else:
		point["b'EnumSystemLocalesEx'"] = 0

	if "b'EnumThreadWindows'" in xk:
		point["b'EnumThreadWindows'"] = 1
	else:
		point["b'EnumThreadWindows'"] = 0

	if "b'EnumWindows'" in xk:
		point["b'EnumWindows'"] = 1
	else:
		point["b'EnumWindows'"] = 0

	if "b'EnumerateLoadedModules'" in xk:
		point["b'EnumerateLoadedModules'"] = 1
	else:
		point["b'EnumerateLoadedModules'"] = 0

	if "b'EqualRect'" in xk:
		point["b'EqualRect'"] = 1
	else:
		point["b'EqualRect'"] = 0

	if "b'EqualRgn'" in xk:
		point["b'EqualRgn'"] = 1
	else:
		point["b'EqualRgn'"] = 0

	if "b'EqualSid'" in xk:
		point["b'EqualSid'"] = 1
	else:
		point["b'EqualSid'"] = 0

	if "b'EraseTape'" in xk:
		point["b'EraseTape'"] = 1
	else:
		point["b'EraseTape'"] = 0

	if "b'ErrMsg'" in xk:
		point["b'ErrMsg'"] = 1
	else:
		point["b'ErrMsg'"] = 0

	if "b'ErrMsgParam'" in xk:
		point["b'ErrMsgParam'"] = 1
	else:
		point["b'ErrMsgParam'"] = 0

	if "b'Escape'" in xk:
		point["b'Escape'"] = 1
	else:
		point["b'Escape'"] = 0

	if "b'ExAllocatePool'" in xk:
		point["b'ExAllocatePool'"] = 1
	else:
		point["b'ExAllocatePool'"] = 0

	if "b'ExAllocatePoolWithTag'" in xk:
		point["b'ExAllocatePoolWithTag'"] = 1
	else:
		point["b'ExAllocatePoolWithTag'"] = 0

	if "b'ExFreePool'" in xk:
		point["b'ExFreePool'"] = 1
	else:
		point["b'ExFreePool'"] = 0

	if "b'ExFreePoolWithTag'" in xk:
		point["b'ExFreePoolWithTag'"] = 1
	else:
		point["b'ExFreePoolWithTag'"] = 0

	if "b'ExSystemTimeToLocalTime'" in xk:
		point["b'ExSystemTimeToLocalTime'"] = 1
	else:
		point["b'ExSystemTimeToLocalTime'"] = 0

	if "b'ExcludeClipRect'" in xk:
		point["b'ExcludeClipRect'"] = 1
	else:
		point["b'ExcludeClipRect'"] = 0

	if "b'ExitProcess'" in xk:
		point["b'ExitProcess'"] = 1
	else:
		point["b'ExitProcess'"] = 0

	if "b'ExitThread'" in xk:
		point["b'ExitThread'"] = 1
	else:
		point["b'ExitThread'"] = 0

	if "b'ExitWindowsEx'" in xk:
		point["b'ExitWindowsEx'"] = 1
	else:
		point["b'ExitWindowsEx'"] = 0

	if "b'ExpandEnvironmentStringsA'" in xk:
		point["b'ExpandEnvironmentStringsA'"] = 1
	else:
		point["b'ExpandEnvironmentStringsA'"] = 0

	if "b'ExpandEnvironmentStringsW'" in xk:
		point["b'ExpandEnvironmentStringsW'"] = 1
	else:
		point["b'ExpandEnvironmentStringsW'"] = 0

	if "b'ExpandEnvironmentStringsForUserA'" in xk:
		point["b'ExpandEnvironmentStringsForUserA'"] = 1
	else:
		point["b'ExpandEnvironmentStringsForUserA'"] = 0

	if "b'ExtCreatePen'" in xk:
		point["b'ExtCreatePen'"] = 1
	else:
		point["b'ExtCreatePen'"] = 0

	if "b'ExtEscape'" in xk:
		point["b'ExtEscape'"] = 1
	else:
		point["b'ExtEscape'"] = 0

	if "b'ExtFloodFill'" in xk:
		point["b'ExtFloodFill'"] = 1
	else:
		point["b'ExtFloodFill'"] = 0

	if "b'ExtSelectClipRgn'" in xk:
		point["b'ExtSelectClipRgn'"] = 1
	else:
		point["b'ExtSelectClipRgn'"] = 0

	if "b'ExtTextOutA'" in xk:
		point["b'ExtTextOutA'"] = 1
	else:
		point["b'ExtTextOutA'"] = 0

	if "b'ExtTextOutW'" in xk:
		point["b'ExtTextOutW'"] = 1
	else:
		point["b'ExtTextOutW'"] = 0

	if "b'ExtractAssociatedIconW'" in xk:
		point["b'ExtractAssociatedIconW'"] = 1
	else:
		point["b'ExtractAssociatedIconW'"] = 0

	if "b'ExtractIconA'" in xk:
		point["b'ExtractIconA'"] = 1
	else:
		point["b'ExtractIconA'"] = 0

	if "b'ExtractIconW'" in xk:
		point["b'ExtractIconW'"] = 1
	else:
		point["b'ExtractIconW'"] = 0

	if "b'ExtractIconExA'" in xk:
		point["b'ExtractIconExA'"] = 1
	else:
		point["b'ExtractIconExA'"] = 0

	if "b'ExtractIconExW'" in xk:
		point["b'ExtractIconExW'"] = 1
	else:
		point["b'ExtractIconExW'"] = 0

	if "b'FDICopy'" in xk:
		point["b'FDICopy'"] = 1
	else:
		point["b'FDICopy'"] = 0

	if "b'FDICreate'" in xk:
		point["b'FDICreate'"] = 1
	else:
		point["b'FDICreate'"] = 0

	if "b'FDIDestroy'" in xk:
		point["b'FDIDestroy'"] = 1
	else:
		point["b'FDIDestroy'"] = 0

	if "b'FailClusterResource'" in xk:
		point["b'FailClusterResource'"] = 1
	else:
		point["b'FailClusterResource'"] = 0

	if "b'FatalAppExitA'" in xk:
		point["b'FatalAppExitA'"] = 1
	else:
		point["b'FatalAppExitA'"] = 0

	if "b'FaultInIEFeature'" in xk:
		point["b'FaultInIEFeature'"] = 1
	else:
		point["b'FaultInIEFeature'"] = 0

	if "b'FileTimeToDosDateTime'" in xk:
		point["b'FileTimeToDosDateTime'"] = 1
	else:
		point["b'FileTimeToDosDateTime'"] = 0

	if "b'FileTimeToLocalFileTime'" in xk:
		point["b'FileTimeToLocalFileTime'"] = 1
	else:
		point["b'FileTimeToLocalFileTime'"] = 0

	if "b'FileTimeToSystemTime'" in xk:
		point["b'FileTimeToSystemTime'"] = 1
	else:
		point["b'FileTimeToSystemTime'"] = 0

	if "b'FillConsoleOutputAttribute'" in xk:
		point["b'FillConsoleOutputAttribute'"] = 1
	else:
		point["b'FillConsoleOutputAttribute'"] = 0

	if "b'FillConsoleOutputCharacterW'" in xk:
		point["b'FillConsoleOutputCharacterW'"] = 1
	else:
		point["b'FillConsoleOutputCharacterW'"] = 0

	if "b'FillRect'" in xk:
		point["b'FillRect'"] = 1
	else:
		point["b'FillRect'"] = 0

	if "b'FillRgn'" in xk:
		point["b'FillRgn'"] = 1
	else:
		point["b'FillRgn'"] = 0

	if "b'FindAtomA'" in xk:
		point["b'FindAtomA'"] = 1
	else:
		point["b'FindAtomA'"] = 0

	if "b'FindAtomW'" in xk:
		point["b'FindAtomW'"] = 1
	else:
		point["b'FindAtomW'"] = 0

	if "b'FindClose'" in xk:
		point["b'FindClose'"] = 1
	else:
		point["b'FindClose'"] = 0

	if "b'FindCloseUrlCache'" in xk:
		point["b'FindCloseUrlCache'"] = 1
	else:
		point["b'FindCloseUrlCache'"] = 0

	if "b'FindExecutableA'" in xk:
		point["b'FindExecutableA'"] = 1
	else:
		point["b'FindExecutableA'"] = 0

	if "b'FindExecutableW'" in xk:
		point["b'FindExecutableW'"] = 1
	else:
		point["b'FindExecutableW'"] = 0

	if "b'FindFileInSearchPath'" in xk:
		point["b'FindFileInSearchPath'"] = 1
	else:
		point["b'FindFileInSearchPath'"] = 0

	if "b'FindFirstChangeNotificationA'" in xk:
		point["b'FindFirstChangeNotificationA'"] = 1
	else:
		point["b'FindFirstChangeNotificationA'"] = 0

	if "b'FindFirstChangeNotificationW'" in xk:
		point["b'FindFirstChangeNotificationW'"] = 1
	else:
		point["b'FindFirstChangeNotificationW'"] = 0

	if "b'FindFirstFileA'" in xk:
		point["b'FindFirstFileA'"] = 1
	else:
		point["b'FindFirstFileA'"] = 0

	if "b'FindFirstFileW'" in xk:
		point["b'FindFirstFileW'"] = 1
	else:
		point["b'FindFirstFileW'"] = 0

	if "b'FindFirstFileExA'" in xk:
		point["b'FindFirstFileExA'"] = 1
	else:
		point["b'FindFirstFileExA'"] = 0

	if "b'FindFirstFileExW'" in xk:
		point["b'FindFirstFileExW'"] = 1
	else:
		point["b'FindFirstFileExW'"] = 0

	if "b'FindFirstFreeAce'" in xk:
		point["b'FindFirstFreeAce'"] = 1
	else:
		point["b'FindFirstFreeAce'"] = 0

	if "b'FindFirstUrlCacheEntryA'" in xk:
		point["b'FindFirstUrlCacheEntryA'"] = 1
	else:
		point["b'FindFirstUrlCacheEntryA'"] = 0

	if "b'FindFirstUrlCacheEntryW'" in xk:
		point["b'FindFirstUrlCacheEntryW'"] = 1
	else:
		point["b'FindFirstUrlCacheEntryW'"] = 0

	if "b'FindFirstVolumeW'" in xk:
		point["b'FindFirstVolumeW'"] = 1
	else:
		point["b'FindFirstVolumeW'"] = 0

	if "b'FindFirstVolumeMountPointW'" in xk:
		point["b'FindFirstVolumeMountPointW'"] = 1
	else:
		point["b'FindFirstVolumeMountPointW'"] = 0

	if "b'FindMimeFromData'" in xk:
		point["b'FindMimeFromData'"] = 1
	else:
		point["b'FindMimeFromData'"] = 0

	if "b'FindNextFileA'" in xk:
		point["b'FindNextFileA'"] = 1
	else:
		point["b'FindNextFileA'"] = 0

	if "b'FindNextFileW'" in xk:
		point["b'FindNextFileW'"] = 1
	else:
		point["b'FindNextFileW'"] = 0

	if "b'FindNextUrlCacheEntryA'" in xk:
		point["b'FindNextUrlCacheEntryA'"] = 1
	else:
		point["b'FindNextUrlCacheEntryA'"] = 0

	if "b'FindNextUrlCacheEntryW'" in xk:
		point["b'FindNextUrlCacheEntryW'"] = 1
	else:
		point["b'FindNextUrlCacheEntryW'"] = 0

	if "b'FindNextVolumeW'" in xk:
		point["b'FindNextVolumeW'"] = 1
	else:
		point["b'FindNextVolumeW'"] = 0

	if "b'FindResourceA'" in xk:
		point["b'FindResourceA'"] = 1
	else:
		point["b'FindResourceA'"] = 0

	if "b'FindResourceW'" in xk:
		point["b'FindResourceW'"] = 1
	else:
		point["b'FindResourceW'"] = 0

	if "b'FindResourceExA'" in xk:
		point["b'FindResourceExA'"] = 1
	else:
		point["b'FindResourceExA'"] = 0

	if "b'FindResourceExW'" in xk:
		point["b'FindResourceExW'"] = 1
	else:
		point["b'FindResourceExW'"] = 0

	if "b'FindSheet'" in xk:
		point["b'FindSheet'"] = 1
	else:
		point["b'FindSheet'"] = 0

	if "b'FindVolumeClose'" in xk:
		point["b'FindVolumeClose'"] = 1
	else:
		point["b'FindVolumeClose'"] = 0

	if "b'FindVolumeMountPointClose'" in xk:
		point["b'FindVolumeMountPointClose'"] = 1
	else:
		point["b'FindVolumeMountPointClose'"] = 0

	if "b'FindWindowA'" in xk:
		point["b'FindWindowA'"] = 1
	else:
		point["b'FindWindowA'"] = 0

	if "b'FindWindowW'" in xk:
		point["b'FindWindowW'"] = 1
	else:
		point["b'FindWindowW'"] = 0

	if "b'FindWindowExA'" in xk:
		point["b'FindWindowExA'"] = 1
	else:
		point["b'FindWindowExA'"] = 0

	if "b'FindWindowExW'" in xk:
		point["b'FindWindowExW'"] = 1
	else:
		point["b'FindWindowExW'"] = 0

	if "b'FixBrushOrgEx'" in xk:
		point["b'FixBrushOrgEx'"] = 1
	else:
		point["b'FixBrushOrgEx'"] = 0

	if "b'FlashWindow'" in xk:
		point["b'FlashWindow'"] = 1
	else:
		point["b'FlashWindow'"] = 0

	if "b'FlashWindowEx'" in xk:
		point["b'FlashWindowEx'"] = 1
	else:
		point["b'FlashWindowEx'"] = 0

	if "b'FlatSB_GetScrollInfo'" in xk:
		point["b'FlatSB_GetScrollInfo'"] = 1
	else:
		point["b'FlatSB_GetScrollInfo'"] = 0

	if "b'FlattenPath'" in xk:
		point["b'FlattenPath'"] = 1
	else:
		point["b'FlattenPath'"] = 0

	if "b'FlsAlloc'" in xk:
		point["b'FlsAlloc'"] = 1
	else:
		point["b'FlsAlloc'"] = 0

	if "b'FlsFree'" in xk:
		point["b'FlsFree'"] = 1
	else:
		point["b'FlsFree'"] = 0

	if "b'FlsGetValue'" in xk:
		point["b'FlsGetValue'"] = 1
	else:
		point["b'FlsGetValue'"] = 0

	if "b'FlsSetValue'" in xk:
		point["b'FlsSetValue'"] = 1
	else:
		point["b'FlsSetValue'"] = 0

	if "b'FlushConsoleInputBuffer'" in xk:
		point["b'FlushConsoleInputBuffer'"] = 1
	else:
		point["b'FlushConsoleInputBuffer'"] = 0

	if "b'FlushFileBuffers'" in xk:
		point["b'FlushFileBuffers'"] = 1
	else:
		point["b'FlushFileBuffers'"] = 0

	if "b'FlushInstructionCache'" in xk:
		point["b'FlushInstructionCache'"] = 1
	else:
		point["b'FlushInstructionCache'"] = 0

	if "b'FlushViewOfFile'" in xk:
		point["b'FlushViewOfFile'"] = 1
	else:
		point["b'FlushViewOfFile'"] = 0

	if "b'FoldStringW'" in xk:
		point["b'FoldStringW'"] = 1
	else:
		point["b'FoldStringW'"] = 0

	if "b'FormatMessageA'" in xk:
		point["b'FormatMessageA'"] = 1
	else:
		point["b'FormatMessageA'"] = 0

	if "b'FormatMessageW'" in xk:
		point["b'FormatMessageW'"] = 1
	else:
		point["b'FormatMessageW'"] = 0

	if "b'FrameRect'" in xk:
		point["b'FrameRect'"] = 1
	else:
		point["b'FrameRect'"] = 0

	if "b'FrameRgn'" in xk:
		point["b'FrameRgn'"] = 1
	else:
		point["b'FrameRgn'"] = 0

	if "b'FreeConsole'" in xk:
		point["b'FreeConsole'"] = 1
	else:
		point["b'FreeConsole'"] = 0

	if "b'FreeDDElParam'" in xk:
		point["b'FreeDDElParam'"] = 1
	else:
		point["b'FreeDDElParam'"] = 0

	if "b'FreeEnvironmentStringsA'" in xk:
		point["b'FreeEnvironmentStringsA'"] = 1
	else:
		point["b'FreeEnvironmentStringsA'"] = 0

	if "b'FreeEnvironmentStringsW'" in xk:
		point["b'FreeEnvironmentStringsW'"] = 1
	else:
		point["b'FreeEnvironmentStringsW'"] = 0

	if "b'FreeGPOListA'" in xk:
		point["b'FreeGPOListA'"] = 1
	else:
		point["b'FreeGPOListA'"] = 0

	if "b'FreeLibrary'" in xk:
		point["b'FreeLibrary'"] = 1
	else:
		point["b'FreeLibrary'"] = 0

	if "b'FreeLibraryAndExitThread'" in xk:
		point["b'FreeLibraryAndExitThread'"] = 1
	else:
		point["b'FreeLibraryAndExitThread'"] = 0

	if "b'FreeResource'" in xk:
		point["b'FreeResource'"] = 1
	else:
		point["b'FreeResource'"] = 0

	if "b'FreeSid'" in xk:
		point["b'FreeSid'"] = 1
	else:
		point["b'FreeSid'"] = 0

	if "b'FtpFindFirstFileA'" in xk:
		point["b'FtpFindFirstFileA'"] = 1
	else:
		point["b'FtpFindFirstFileA'"] = 0

	if "b'FtpGetFileA'" in xk:
		point["b'FtpGetFileA'"] = 1
	else:
		point["b'FtpGetFileA'"] = 0

	if "b'FtpGetFileSize'" in xk:
		point["b'FtpGetFileSize'"] = 1
	else:
		point["b'FtpGetFileSize'"] = 0

	if "b'FtpOpenFileA'" in xk:
		point["b'FtpOpenFileA'"] = 1
	else:
		point["b'FtpOpenFileA'"] = 0

	if "b'FtpOpenFileW'" in xk:
		point["b'FtpOpenFileW'"] = 1
	else:
		point["b'FtpOpenFileW'"] = 0

	if "b'FtpPutFileA'" in xk:
		point["b'FtpPutFileA'"] = 1
	else:
		point["b'FtpPutFileA'"] = 0

	if "b'GdiCleanCacheDC'" in xk:
		point["b'GdiCleanCacheDC'"] = 1
	else:
		point["b'GdiCleanCacheDC'"] = 0

	if "b'GdiComment'" in xk:
		point["b'GdiComment'"] = 1
	else:
		point["b'GdiComment'"] = 0

	if "b'GdiEntry10'" in xk:
		point["b'GdiEntry10'"] = 1
	else:
		point["b'GdiEntry10'"] = 0

	if "b'GdiFlush'" in xk:
		point["b'GdiFlush'"] = 1
	else:
		point["b'GdiFlush'"] = 0

	if "b'GdiGetLocalDC'" in xk:
		point["b'GdiGetLocalDC'"] = 1
	else:
		point["b'GdiGetLocalDC'"] = 0

	if "b'GdiGetPageCount'" in xk:
		point["b'GdiGetPageCount'"] = 1
	else:
		point["b'GdiGetPageCount'"] = 0

	if "b'GdiGradientFill'" in xk:
		point["b'GdiGradientFill'"] = 1
	else:
		point["b'GdiGradientFill'"] = 0

	if "b'GdiInitializeLanguagePack'" in xk:
		point["b'GdiInitializeLanguagePack'"] = 1
	else:
		point["b'GdiInitializeLanguagePack'"] = 0

	if "b'GdiProcessSetup'" in xk:
		point["b'GdiProcessSetup'"] = 1
	else:
		point["b'GdiProcessSetup'"] = 0

	if "b'GdiQueryTable'" in xk:
		point["b'GdiQueryTable'"] = 1
	else:
		point["b'GdiQueryTable'"] = 0

	if "b'GdiResetDCEMF'" in xk:
		point["b'GdiResetDCEMF'"] = 1
	else:
		point["b'GdiResetDCEMF'"] = 0

	if "b'GdiSetBatchLimit'" in xk:
		point["b'GdiSetBatchLimit'"] = 1
	else:
		point["b'GdiSetBatchLimit'"] = 0

	if "b'GdiStartPageEMF'" in xk:
		point["b'GdiStartPageEMF'"] = 1
	else:
		point["b'GdiStartPageEMF'"] = 0

	if "b'GdiSwapBuffers'" in xk:
		point["b'GdiSwapBuffers'"] = 1
	else:
		point["b'GdiSwapBuffers'"] = 0

	if "b'GdiValidateHandle'" in xk:
		point["b'GdiValidateHandle'"] = 1
	else:
		point["b'GdiValidateHandle'"] = 0

	if "b'GdipAddPathArc'" in xk:
		point["b'GdipAddPathArc'"] = 1
	else:
		point["b'GdipAddPathArc'"] = 0

	if "b'GdipAlloc'" in xk:
		point["b'GdipAlloc'"] = 1
	else:
		point["b'GdipAlloc'"] = 0

	if "b'GdipBitmapLockBits'" in xk:
		point["b'GdipBitmapLockBits'"] = 1
	else:
		point["b'GdipBitmapLockBits'"] = 0

	if "b'GdipBitmapUnlockBits'" in xk:
		point["b'GdipBitmapUnlockBits'"] = 1
	else:
		point["b'GdipBitmapUnlockBits'"] = 0

	if "b'GdipCloneBrush'" in xk:
		point["b'GdipCloneBrush'"] = 1
	else:
		point["b'GdipCloneBrush'"] = 0

	if "b'GdipCloneImage'" in xk:
		point["b'GdipCloneImage'"] = 1
	else:
		point["b'GdipCloneImage'"] = 0

	if "b'GdipCreateBitmapFromFile'" in xk:
		point["b'GdipCreateBitmapFromFile'"] = 1
	else:
		point["b'GdipCreateBitmapFromFile'"] = 0

	if "b'GdipCreateBitmapFromFileICM'" in xk:
		point["b'GdipCreateBitmapFromFileICM'"] = 1
	else:
		point["b'GdipCreateBitmapFromFileICM'"] = 0

	if "b'GdipCreateBitmapFromHBITMAP'" in xk:
		point["b'GdipCreateBitmapFromHBITMAP'"] = 1
	else:
		point["b'GdipCreateBitmapFromHBITMAP'"] = 0

	if "b'GdipCreateBitmapFromScan0'" in xk:
		point["b'GdipCreateBitmapFromScan0'"] = 1
	else:
		point["b'GdipCreateBitmapFromScan0'"] = 0

	if "b'GdipCreateBitmapFromStream'" in xk:
		point["b'GdipCreateBitmapFromStream'"] = 1
	else:
		point["b'GdipCreateBitmapFromStream'"] = 0

	if "b'GdipCreateBitmapFromStreamICM'" in xk:
		point["b'GdipCreateBitmapFromStreamICM'"] = 1
	else:
		point["b'GdipCreateBitmapFromStreamICM'"] = 0

	if "b'GdipCreateFont'" in xk:
		point["b'GdipCreateFont'"] = 1
	else:
		point["b'GdipCreateFont'"] = 0

	if "b'GdipCreateFontFamilyFromName'" in xk:
		point["b'GdipCreateFontFamilyFromName'"] = 1
	else:
		point["b'GdipCreateFontFamilyFromName'"] = 0

	if "b'GdipCreateFromHDC'" in xk:
		point["b'GdipCreateFromHDC'"] = 1
	else:
		point["b'GdipCreateFromHDC'"] = 0

	if "b'GdipCreateHBITMAPFromBitmap'" in xk:
		point["b'GdipCreateHBITMAPFromBitmap'"] = 1
	else:
		point["b'GdipCreateHBITMAPFromBitmap'"] = 0

	if "b'GdipCreateImageAttributes'" in xk:
		point["b'GdipCreateImageAttributes'"] = 1
	else:
		point["b'GdipCreateImageAttributes'"] = 0

	if "b'GdipCreateMatrix'" in xk:
		point["b'GdipCreateMatrix'"] = 1
	else:
		point["b'GdipCreateMatrix'"] = 0

	if "b'GdipCreatePen1'" in xk:
		point["b'GdipCreatePen1'"] = 1
	else:
		point["b'GdipCreatePen1'"] = 0

	if "b'GdipCreateSolidFill'" in xk:
		point["b'GdipCreateSolidFill'"] = 1
	else:
		point["b'GdipCreateSolidFill'"] = 0

	if "b'GdipCreateStringFormat'" in xk:
		point["b'GdipCreateStringFormat'"] = 1
	else:
		point["b'GdipCreateStringFormat'"] = 0

	if "b'GdipDeleteBrush'" in xk:
		point["b'GdipDeleteBrush'"] = 1
	else:
		point["b'GdipDeleteBrush'"] = 0

	if "b'GdipDeleteFont'" in xk:
		point["b'GdipDeleteFont'"] = 1
	else:
		point["b'GdipDeleteFont'"] = 0

	if "b'GdipDeleteFontFamily'" in xk:
		point["b'GdipDeleteFontFamily'"] = 1
	else:
		point["b'GdipDeleteFontFamily'"] = 0

	if "b'GdipDeleteGraphics'" in xk:
		point["b'GdipDeleteGraphics'"] = 1
	else:
		point["b'GdipDeleteGraphics'"] = 0

	if "b'GdipDeleteMatrix'" in xk:
		point["b'GdipDeleteMatrix'"] = 1
	else:
		point["b'GdipDeleteMatrix'"] = 0

	if "b'GdipDeletePen'" in xk:
		point["b'GdipDeletePen'"] = 1
	else:
		point["b'GdipDeletePen'"] = 0

	if "b'GdipDeleteStringFormat'" in xk:
		point["b'GdipDeleteStringFormat'"] = 1
	else:
		point["b'GdipDeleteStringFormat'"] = 0

	if "b'GdipDisposeImage'" in xk:
		point["b'GdipDisposeImage'"] = 1
	else:
		point["b'GdipDisposeImage'"] = 0

	if "b'GdipDisposeImageAttributes'" in xk:
		point["b'GdipDisposeImageAttributes'"] = 1
	else:
		point["b'GdipDisposeImageAttributes'"] = 0

	if "b'GdipDrawImageI'" in xk:
		point["b'GdipDrawImageI'"] = 1
	else:
		point["b'GdipDrawImageI'"] = 0

	if "b'GdipDrawImageRectI'" in xk:
		point["b'GdipDrawImageRectI'"] = 1
	else:
		point["b'GdipDrawImageRectI'"] = 0

	if "b'GdipDrawImageRectRect'" in xk:
		point["b'GdipDrawImageRectRect'"] = 1
	else:
		point["b'GdipDrawImageRectRect'"] = 0

	if "b'GdipDrawImageRectRectI'" in xk:
		point["b'GdipDrawImageRectRectI'"] = 1
	else:
		point["b'GdipDrawImageRectRectI'"] = 0

	if "b'GdipDrawLineI'" in xk:
		point["b'GdipDrawLineI'"] = 1
	else:
		point["b'GdipDrawLineI'"] = 0

	if "b'GdipDrawString'" in xk:
		point["b'GdipDrawString'"] = 1
	else:
		point["b'GdipDrawString'"] = 0

	if "b'GdipFree'" in xk:
		point["b'GdipFree'"] = 1
	else:
		point["b'GdipFree'"] = 0

	if "b'GdipGetDC'" in xk:
		point["b'GdipGetDC'"] = 1
	else:
		point["b'GdipGetDC'"] = 0

	if "b'GdipGetFontSize'" in xk:
		point["b'GdipGetFontSize'"] = 1
	else:
		point["b'GdipGetFontSize'"] = 0

	if "b'GdipGetImageEncoders'" in xk:
		point["b'GdipGetImageEncoders'"] = 1
	else:
		point["b'GdipGetImageEncoders'"] = 0

	if "b'GdipGetImageEncodersSize'" in xk:
		point["b'GdipGetImageEncodersSize'"] = 1
	else:
		point["b'GdipGetImageEncodersSize'"] = 0

	if "b'GdipGetImageGraphicsContext'" in xk:
		point["b'GdipGetImageGraphicsContext'"] = 1
	else:
		point["b'GdipGetImageGraphicsContext'"] = 0

	if "b'GdipGetImageHeight'" in xk:
		point["b'GdipGetImageHeight'"] = 1
	else:
		point["b'GdipGetImageHeight'"] = 0

	if "b'GdipGetImagePalette'" in xk:
		point["b'GdipGetImagePalette'"] = 1
	else:
		point["b'GdipGetImagePalette'"] = 0

	if "b'GdipGetImagePaletteSize'" in xk:
		point["b'GdipGetImagePaletteSize'"] = 1
	else:
		point["b'GdipGetImagePaletteSize'"] = 0

	if "b'GdipGetImagePixelFormat'" in xk:
		point["b'GdipGetImagePixelFormat'"] = 1
	else:
		point["b'GdipGetImagePixelFormat'"] = 0

	if "b'GdipGetImageWidth'" in xk:
		point["b'GdipGetImageWidth'"] = 1
	else:
		point["b'GdipGetImageWidth'"] = 0

	if "b'GdipGraphicsClear'" in xk:
		point["b'GdipGraphicsClear'"] = 1
	else:
		point["b'GdipGraphicsClear'"] = 0

	if "b'GdipLoadImageFromStream'" in xk:
		point["b'GdipLoadImageFromStream'"] = 1
	else:
		point["b'GdipLoadImageFromStream'"] = 0

	if "b'GdipLoadImageFromStreamICM'" in xk:
		point["b'GdipLoadImageFromStreamICM'"] = 1
	else:
		point["b'GdipLoadImageFromStreamICM'"] = 0

	if "b'GdipMeasureString'" in xk:
		point["b'GdipMeasureString'"] = 1
	else:
		point["b'GdipMeasureString'"] = 0

	if "b'GdipReleaseDC'" in xk:
		point["b'GdipReleaseDC'"] = 1
	else:
		point["b'GdipReleaseDC'"] = 0

	if "b'GdipSaveImageToFile'" in xk:
		point["b'GdipSaveImageToFile'"] = 1
	else:
		point["b'GdipSaveImageToFile'"] = 0

	if "b'GdipSaveImageToStream'" in xk:
		point["b'GdipSaveImageToStream'"] = 1
	else:
		point["b'GdipSaveImageToStream'"] = 0

	if "b'GdipSetImageAttributesColorKeys'" in xk:
		point["b'GdipSetImageAttributesColorKeys'"] = 1
	else:
		point["b'GdipSetImageAttributesColorKeys'"] = 0

	if "b'GdipSetImageAttributesColorMatrix'" in xk:
		point["b'GdipSetImageAttributesColorMatrix'"] = 1
	else:
		point["b'GdipSetImageAttributesColorMatrix'"] = 0

	if "b'GdipSetInterpolationMode'" in xk:
		point["b'GdipSetInterpolationMode'"] = 1
	else:
		point["b'GdipSetInterpolationMode'"] = 0

	if "b'GdipSetSmoothingMode'" in xk:
		point["b'GdipSetSmoothingMode'"] = 1
	else:
		point["b'GdipSetSmoothingMode'"] = 0

	if "b'GdipSetStringFormatAlign'" in xk:
		point["b'GdipSetStringFormatAlign'"] = 1
	else:
		point["b'GdipSetStringFormatAlign'"] = 0

	if "b'GdipSetStringFormatLineAlign'" in xk:
		point["b'GdipSetStringFormatLineAlign'"] = 1
	else:
		point["b'GdipSetStringFormatLineAlign'"] = 0

	if "b'GdiplusShutdown'" in xk:
		point["b'GdiplusShutdown'"] = 1
	else:
		point["b'GdiplusShutdown'"] = 0

	if "b'GdiplusStartup'" in xk:
		point["b'GdiplusStartup'"] = 1
	else:
		point["b'GdiplusStartup'"] = 0

	if "b'GetACP'" in xk:
		point["b'GetACP'"] = 1
	else:
		point["b'GetACP'"] = 0

	if "b'GetAce'" in xk:
		point["b'GetAce'"] = 1
	else:
		point["b'GetAce'"] = 0

	if "b'GetAclInformation'" in xk:
		point["b'GetAclInformation'"] = 1
	else:
		point["b'GetAclInformation'"] = 0

	if "b'GetActiveObject'" in xk:
		point["b'GetActiveObject'"] = 1
	else:
		point["b'GetActiveObject'"] = 0

	if "b'GetActiveWindow'" in xk:
		point["b'GetActiveWindow'"] = 1
	else:
		point["b'GetActiveWindow'"] = 0

	if "b'GetAdaptersInfo'" in xk:
		point["b'GetAdaptersInfo'"] = 1
	else:
		point["b'GetAdaptersInfo'"] = 0

	if "b'GetAltTabInfoA'" in xk:
		point["b'GetAltTabInfoA'"] = 1
	else:
		point["b'GetAltTabInfoA'"] = 0

	if "b'GetAncestor'" in xk:
		point["b'GetAncestor'"] = 1
	else:
		point["b'GetAncestor'"] = 0

	if "b'GetArcDirection'" in xk:
		point["b'GetArcDirection'"] = 1
	else:
		point["b'GetArcDirection'"] = 0

	if "b'GetAsyncKeyState'" in xk:
		point["b'GetAsyncKeyState'"] = 1
	else:
		point["b'GetAsyncKeyState'"] = 0

	if "b'GetAtomNameA'" in xk:
		point["b'GetAtomNameA'"] = 1
	else:
		point["b'GetAtomNameA'"] = 0

	if "b'GetAtomNameW'" in xk:
		point["b'GetAtomNameW'"] = 1
	else:
		point["b'GetAtomNameW'"] = 0

	if "b'GetBinaryTypeA'" in xk:
		point["b'GetBinaryTypeA'"] = 1
	else:
		point["b'GetBinaryTypeA'"] = 0

	if "b'GetBinaryTypeW'" in xk:
		point["b'GetBinaryTypeW'"] = 1
	else:
		point["b'GetBinaryTypeW'"] = 0

	if "b'GetBitmapBits'" in xk:
		point["b'GetBitmapBits'"] = 1
	else:
		point["b'GetBitmapBits'"] = 0

	if "b'GetBitmapDimensionEx'" in xk:
		point["b'GetBitmapDimensionEx'"] = 1
	else:
		point["b'GetBitmapDimensionEx'"] = 0

	if "b'GetBkColor'" in xk:
		point["b'GetBkColor'"] = 1
	else:
		point["b'GetBkColor'"] = 0

	if "b'GetBoundsRect'" in xk:
		point["b'GetBoundsRect'"] = 1
	else:
		point["b'GetBoundsRect'"] = 0

	if "b'GetBrushOrgEx'" in xk:
		point["b'GetBrushOrgEx'"] = 1
	else:
		point["b'GetBrushOrgEx'"] = 0

	if "b'GetCPInfo'" in xk:
		point["b'GetCPInfo'"] = 1
	else:
		point["b'GetCPInfo'"] = 0

	if "b'GetCPInfoExW'" in xk:
		point["b'GetCPInfoExW'"] = 1
	else:
		point["b'GetCPInfoExW'"] = 0

	if "b'GetCalendarInfoA'" in xk:
		point["b'GetCalendarInfoA'"] = 1
	else:
		point["b'GetCalendarInfoA'"] = 0

	if "b'GetCalendarInfoW'" in xk:
		point["b'GetCalendarInfoW'"] = 1
	else:
		point["b'GetCalendarInfoW'"] = 0

	if "b'GetCapture'" in xk:
		point["b'GetCapture'"] = 1
	else:
		point["b'GetCapture'"] = 0

	if "b'GetCaretPos'" in xk:
		point["b'GetCaretPos'"] = 1
	else:
		point["b'GetCaretPos'"] = 0

	if "b'GetCharWidthA'" in xk:
		point["b'GetCharWidthA'"] = 1
	else:
		point["b'GetCharWidthA'"] = 0

	if "b'GetCharWidth32A'" in xk:
		point["b'GetCharWidth32A'"] = 1
	else:
		point["b'GetCharWidth32A'"] = 0

	if "b'GetCharWidth32W'" in xk:
		point["b'GetCharWidth32W'"] = 1
	else:
		point["b'GetCharWidth32W'"] = 0

	if "b'GetClassInfoA'" in xk:
		point["b'GetClassInfoA'"] = 1
	else:
		point["b'GetClassInfoA'"] = 0

	if "b'GetClassInfoW'" in xk:
		point["b'GetClassInfoW'"] = 1
	else:
		point["b'GetClassInfoW'"] = 0

	if "b'GetClassInfoExA'" in xk:
		point["b'GetClassInfoExA'"] = 1
	else:
		point["b'GetClassInfoExA'"] = 0

	if "b'GetClassInfoExW'" in xk:
		point["b'GetClassInfoExW'"] = 1
	else:
		point["b'GetClassInfoExW'"] = 0

	if "b'GetClassLongA'" in xk:
		point["b'GetClassLongA'"] = 1
	else:
		point["b'GetClassLongA'"] = 0

	if "b'GetClassLongW'" in xk:
		point["b'GetClassLongW'"] = 1
	else:
		point["b'GetClassLongW'"] = 0

	if "b'GetClassNameA'" in xk:
		point["b'GetClassNameA'"] = 1
	else:
		point["b'GetClassNameA'"] = 0

	if "b'GetClassNameW'" in xk:
		point["b'GetClassNameW'"] = 1
	else:
		point["b'GetClassNameW'"] = 0

	if "b'GetClientRect'" in xk:
		point["b'GetClientRect'"] = 1
	else:
		point["b'GetClientRect'"] = 0

	if "b'GetClipBox'" in xk:
		point["b'GetClipBox'"] = 1
	else:
		point["b'GetClipBox'"] = 0

	if "b'GetClipboardData'" in xk:
		point["b'GetClipboardData'"] = 1
	else:
		point["b'GetClipboardData'"] = 0

	if "b'GetClipboardFormatNameA'" in xk:
		point["b'GetClipboardFormatNameA'"] = 1
	else:
		point["b'GetClipboardFormatNameA'"] = 0

	if "b'GetClipboardFormatNameW'" in xk:
		point["b'GetClipboardFormatNameW'"] = 1
	else:
		point["b'GetClipboardFormatNameW'"] = 0

	if "b'GetClipboardOwner'" in xk:
		point["b'GetClipboardOwner'"] = 1
	else:
		point["b'GetClipboardOwner'"] = 0

	if "b'GetClipboardSequenceNumber'" in xk:
		point["b'GetClipboardSequenceNumber'"] = 1
	else:
		point["b'GetClipboardSequenceNumber'"] = 0

	if "b'GetClipboardViewer'" in xk:
		point["b'GetClipboardViewer'"] = 1
	else:
		point["b'GetClipboardViewer'"] = 0

	if "b'GetClusterFromNetwork'" in xk:
		point["b'GetClusterFromNetwork'"] = 1
	else:
		point["b'GetClusterFromNetwork'"] = 0

	if "b'GetClusterNodeId'" in xk:
		point["b'GetClusterNodeId'"] = 1
	else:
		point["b'GetClusterNodeId'"] = 0

	if "b'GetComboBoxInfo'" in xk:
		point["b'GetComboBoxInfo'"] = 1
	else:
		point["b'GetComboBoxInfo'"] = 0

	if "b'GetCommProperties'" in xk:
		point["b'GetCommProperties'"] = 1
	else:
		point["b'GetCommProperties'"] = 0

	if "b'GetCommandLineA'" in xk:
		point["b'GetCommandLineA'"] = 1
	else:
		point["b'GetCommandLineA'"] = 0

	if "b'GetCommandLineW'" in xk:
		point["b'GetCommandLineW'"] = 1
	else:
		point["b'GetCommandLineW'"] = 0

	if "b'GetCompressedFileSizeW'" in xk:
		point["b'GetCompressedFileSizeW'"] = 1
	else:
		point["b'GetCompressedFileSizeW'"] = 0

	if "b'GetComputerNameA'" in xk:
		point["b'GetComputerNameA'"] = 1
	else:
		point["b'GetComputerNameA'"] = 0

	if "b'GetComputerNameW'" in xk:
		point["b'GetComputerNameW'"] = 1
	else:
		point["b'GetComputerNameW'"] = 0

	if "b'GetComputerNameExW'" in xk:
		point["b'GetComputerNameExW'"] = 1
	else:
		point["b'GetComputerNameExW'"] = 0

	if "b'GetConsoleAliasA'" in xk:
		point["b'GetConsoleAliasA'"] = 1
	else:
		point["b'GetConsoleAliasA'"] = 0

	if "b'GetConsoleAliasW'" in xk:
		point["b'GetConsoleAliasW'"] = 1
	else:
		point["b'GetConsoleAliasW'"] = 0

	if "b'GetConsoleAliasExesW'" in xk:
		point["b'GetConsoleAliasExesW'"] = 1
	else:
		point["b'GetConsoleAliasExesW'"] = 0

	if "b'GetConsoleAliasExesLinengthA'" in xk:
		point["b'GetConsoleAliasExesLinengthA'"] = 1
	else:
		point["b'GetConsoleAliasExesLinengthA'"] = 0

	if "b'GetConsoleCP'" in xk:
		point["b'GetConsoleCP'"] = 1
	else:
		point["b'GetConsoleCP'"] = 0

	if "b'GetConsoleFontSize'" in xk:
		point["b'GetConsoleFontSize'"] = 1
	else:
		point["b'GetConsoleFontSize'"] = 0

	if "b'GetConsoleHardwareState'" in xk:
		point["b'GetConsoleHardwareState'"] = 1
	else:
		point["b'GetConsoleHardwareState'"] = 0

	if "b'GetConsoleMode'" in xk:
		point["b'GetConsoleMode'"] = 1
	else:
		point["b'GetConsoleMode'"] = 0

	if "b'GetConsoleOutputCP'" in xk:
		point["b'GetConsoleOutputCP'"] = 1
	else:
		point["b'GetConsoleOutputCP'"] = 0

	if "b'GetConsoleScreenBufferInfo'" in xk:
		point["b'GetConsoleScreenBufferInfo'"] = 1
	else:
		point["b'GetConsoleScreenBufferInfo'"] = 0

	if "b'GetConsoleTitleA'" in xk:
		point["b'GetConsoleTitleA'"] = 1
	else:
		point["b'GetConsoleTitleA'"] = 0

	if "b'GetConsoleTitleW'" in xk:
		point["b'GetConsoleTitleW'"] = 1
	else:
		point["b'GetConsoleTitleW'"] = 0

	if "b'GetConsoleWindow'" in xk:
		point["b'GetConsoleWindow'"] = 1
	else:
		point["b'GetConsoleWindow'"] = 0

	if "b'GetCurrentDirectoryA'" in xk:
		point["b'GetCurrentDirectoryA'"] = 1
	else:
		point["b'GetCurrentDirectoryA'"] = 0

	if "b'GetCurrentDirectoryW'" in xk:
		point["b'GetCurrentDirectoryW'"] = 1
	else:
		point["b'GetCurrentDirectoryW'"] = 0

	if "b'GetCurrentHwProfileA'" in xk:
		point["b'GetCurrentHwProfileA'"] = 1
	else:
		point["b'GetCurrentHwProfileA'"] = 0

	if "b'GetCurrentHwProfileW'" in xk:
		point["b'GetCurrentHwProfileW'"] = 1
	else:
		point["b'GetCurrentHwProfileW'"] = 0

	if "b'GetCurrentObject'" in xk:
		point["b'GetCurrentObject'"] = 1
	else:
		point["b'GetCurrentObject'"] = 0

	if "b'GetCurrentPositionEx'" in xk:
		point["b'GetCurrentPositionEx'"] = 1
	else:
		point["b'GetCurrentPositionEx'"] = 0

	if "b'GetCurrentProcess'" in xk:
		point["b'GetCurrentProcess'"] = 1
	else:
		point["b'GetCurrentProcess'"] = 0

	if "b'GetCurrentProcessId'" in xk:
		point["b'GetCurrentProcessId'"] = 1
	else:
		point["b'GetCurrentProcessId'"] = 0

	if "b'GetCurrentThemeName'" in xk:
		point["b'GetCurrentThemeName'"] = 1
	else:
		point["b'GetCurrentThemeName'"] = 0

	if "b'GetCurrentThread'" in xk:
		point["b'GetCurrentThread'"] = 1
	else:
		point["b'GetCurrentThread'"] = 0

	if "b'GetCurrentThreadId'" in xk:
		point["b'GetCurrentThreadId'"] = 1
	else:
		point["b'GetCurrentThreadId'"] = 0

	if "b'GetCursor'" in xk:
		point["b'GetCursor'"] = 1
	else:
		point["b'GetCursor'"] = 0

	if "b'GetCursorInfo'" in xk:
		point["b'GetCursorInfo'"] = 1
	else:
		point["b'GetCursorInfo'"] = 0

	if "b'GetCursorPos'" in xk:
		point["b'GetCursorPos'"] = 1
	else:
		point["b'GetCursorPos'"] = 0

	if "b'GetDC'" in xk:
		point["b'GetDC'"] = 1
	else:
		point["b'GetDC'"] = 0

	if "b'GetDCEx'" in xk:
		point["b'GetDCEx'"] = 1
	else:
		point["b'GetDCEx'"] = 0

	if "b'GetDCOrgEx'" in xk:
		point["b'GetDCOrgEx'"] = 1
	else:
		point["b'GetDCOrgEx'"] = 0

	if "b'GetDIBColorTable'" in xk:
		point["b'GetDIBColorTable'"] = 1
	else:
		point["b'GetDIBColorTable'"] = 0

	if "b'GetDIBits'" in xk:
		point["b'GetDIBits'"] = 1
	else:
		point["b'GetDIBits'"] = 0

	if "b'GetDateFormatA'" in xk:
		point["b'GetDateFormatA'"] = 1
	else:
		point["b'GetDateFormatA'"] = 0

	if "b'GetDateFormatW'" in xk:
		point["b'GetDateFormatW'"] = 1
	else:
		point["b'GetDateFormatW'"] = 0

	if "b'GetDateFormatEx'" in xk:
		point["b'GetDateFormatEx'"] = 1
	else:
		point["b'GetDateFormatEx'"] = 0

	if "b'GetDesktopWindow'" in xk:
		point["b'GetDesktopWindow'"] = 1
	else:
		point["b'GetDesktopWindow'"] = 0

	if "b'GetDeviceCaps'" in xk:
		point["b'GetDeviceCaps'"] = 1
	else:
		point["b'GetDeviceCaps'"] = 0

	if "b'GetDialogBaseUnits'" in xk:
		point["b'GetDialogBaseUnits'"] = 1
	else:
		point["b'GetDialogBaseUnits'"] = 0

	if "b'GetDiskFreeSpaceA'" in xk:
		point["b'GetDiskFreeSpaceA'"] = 1
	else:
		point["b'GetDiskFreeSpaceA'"] = 0

	if "b'GetDiskFreeSpaceW'" in xk:
		point["b'GetDiskFreeSpaceW'"] = 1
	else:
		point["b'GetDiskFreeSpaceW'"] = 0

	if "b'GetDiskFreeSpaceExA'" in xk:
		point["b'GetDiskFreeSpaceExA'"] = 1
	else:
		point["b'GetDiskFreeSpaceExA'"] = 0

	if "b'GetDiskFreeSpaceExW'" in xk:
		point["b'GetDiskFreeSpaceExW'"] = 1
	else:
		point["b'GetDiskFreeSpaceExW'"] = 0

	if "b'GetDlgCtrlID'" in xk:
		point["b'GetDlgCtrlID'"] = 1
	else:
		point["b'GetDlgCtrlID'"] = 0

	if "b'GetDlgItem'" in xk:
		point["b'GetDlgItem'"] = 1
	else:
		point["b'GetDlgItem'"] = 0

	if "b'GetDlgItemInt'" in xk:
		point["b'GetDlgItemInt'"] = 1
	else:
		point["b'GetDlgItemInt'"] = 0

	if "b'GetDlgItemTextA'" in xk:
		point["b'GetDlgItemTextA'"] = 1
	else:
		point["b'GetDlgItemTextA'"] = 0

	if "b'GetDlgItemTextW'" in xk:
		point["b'GetDlgItemTextW'"] = 1
	else:
		point["b'GetDlgItemTextW'"] = 0

	if "b'GetDllDirectoryW'" in xk:
		point["b'GetDllDirectoryW'"] = 1
	else:
		point["b'GetDllDirectoryW'"] = 0

	if "b'GetDoubleClickTime'" in xk:
		point["b'GetDoubleClickTime'"] = 1
	else:
		point["b'GetDoubleClickTime'"] = 0

	if "b'GetDriveTypeA'" in xk:
		point["b'GetDriveTypeA'"] = 1
	else:
		point["b'GetDriveTypeA'"] = 0

	if "b'GetDriveTypeW'" in xk:
		point["b'GetDriveTypeW'"] = 1
	else:
		point["b'GetDriveTypeW'"] = 0

	if "b'GetEnhMetaFileW'" in xk:
		point["b'GetEnhMetaFileW'"] = 1
	else:
		point["b'GetEnhMetaFileW'"] = 0

	if "b'GetEnhMetaFileBits'" in xk:
		point["b'GetEnhMetaFileBits'"] = 1
	else:
		point["b'GetEnhMetaFileBits'"] = 0

	if "b'GetEnhMetaFileHeader'" in xk:
		point["b'GetEnhMetaFileHeader'"] = 1
	else:
		point["b'GetEnhMetaFileHeader'"] = 0

	if "b'GetEnhMetaFilePaletteEntries'" in xk:
		point["b'GetEnhMetaFilePaletteEntries'"] = 1
	else:
		point["b'GetEnhMetaFilePaletteEntries'"] = 0

	if "b'GetEnvironmentStringsA'" in xk:
		point["b'GetEnvironmentStringsA'"] = 1
	else:
		point["b'GetEnvironmentStringsA'"] = 0

	if "b'GetEnvironmentStringsW'" in xk:
		point["b'GetEnvironmentStringsW'"] = 1
	else:
		point["b'GetEnvironmentStringsW'"] = 0

	if "b'GetEnvironmentVariableA'" in xk:
		point["b'GetEnvironmentVariableA'"] = 1
	else:
		point["b'GetEnvironmentVariableA'"] = 0

	if "b'GetEnvironmentVariableW'" in xk:
		point["b'GetEnvironmentVariableW'"] = 1
	else:
		point["b'GetEnvironmentVariableW'"] = 0

	if "b'GetErrorInfo'" in xk:
		point["b'GetErrorInfo'"] = 1
	else:
		point["b'GetErrorInfo'"] = 0

	if "b'GetExitCodeProcess'" in xk:
		point["b'GetExitCodeProcess'"] = 1
	else:
		point["b'GetExitCodeProcess'"] = 0

	if "b'GetExitCodeThread'" in xk:
		point["b'GetExitCodeThread'"] = 1
	else:
		point["b'GetExitCodeThread'"] = 0

	if "b'GetFileAttributesA'" in xk:
		point["b'GetFileAttributesA'"] = 1
	else:
		point["b'GetFileAttributesA'"] = 0

	if "b'GetFileAttributesW'" in xk:
		point["b'GetFileAttributesW'"] = 1
	else:
		point["b'GetFileAttributesW'"] = 0

	if "b'GetFileAttributesExA'" in xk:
		point["b'GetFileAttributesExA'"] = 1
	else:
		point["b'GetFileAttributesExA'"] = 0

	if "b'GetFileAttributesExW'" in xk:
		point["b'GetFileAttributesExW'"] = 1
	else:
		point["b'GetFileAttributesExW'"] = 0

	if "b'GetFileInformationByHandle'" in xk:
		point["b'GetFileInformationByHandle'"] = 1
	else:
		point["b'GetFileInformationByHandle'"] = 0

	if "b'GetFileSecurityW'" in xk:
		point["b'GetFileSecurityW'"] = 1
	else:
		point["b'GetFileSecurityW'"] = 0

	if "b'GetFileSize'" in xk:
		point["b'GetFileSize'"] = 1
	else:
		point["b'GetFileSize'"] = 0

	if "b'GetFileSizeEx'" in xk:
		point["b'GetFileSizeEx'"] = 1
	else:
		point["b'GetFileSizeEx'"] = 0

	if "b'GetFileTime'" in xk:
		point["b'GetFileTime'"] = 1
	else:
		point["b'GetFileTime'"] = 0

	if "b'GetFileTitleA'" in xk:
		point["b'GetFileTitleA'"] = 1
	else:
		point["b'GetFileTitleA'"] = 0

	if "b'GetFileTitleW'" in xk:
		point["b'GetFileTitleW'"] = 1
	else:
		point["b'GetFileTitleW'"] = 0

	if "b'GetFileType'" in xk:
		point["b'GetFileType'"] = 1
	else:
		point["b'GetFileType'"] = 0

	if "b'GetFileVersionInfoA'" in xk:
		point["b'GetFileVersionInfoA'"] = 1
	else:
		point["b'GetFileVersionInfoA'"] = 0

	if "b'GetFileVersionInfoW'" in xk:
		point["b'GetFileVersionInfoW'"] = 1
	else:
		point["b'GetFileVersionInfoW'"] = 0

	if "b'GetFileVersionInfoSizeA'" in xk:
		point["b'GetFileVersionInfoSizeA'"] = 1
	else:
		point["b'GetFileVersionInfoSizeA'"] = 0

	if "b'GetFileVersionInfoSizeW'" in xk:
		point["b'GetFileVersionInfoSizeW'"] = 1
	else:
		point["b'GetFileVersionInfoSizeW'"] = 0

	if "b'GetFirmwareEnvironmentVariableW'" in xk:
		point["b'GetFirmwareEnvironmentVariableW'"] = 1
	else:
		point["b'GetFirmwareEnvironmentVariableW'"] = 0

	if "b'GetFocus'" in xk:
		point["b'GetFocus'"] = 1
	else:
		point["b'GetFocus'"] = 0

	if "b'GetFontData'" in xk:
		point["b'GetFontData'"] = 1
	else:
		point["b'GetFontData'"] = 0

	if "b'GetFontLanguageInfo'" in xk:
		point["b'GetFontLanguageInfo'"] = 1
	else:
		point["b'GetFontLanguageInfo'"] = 0

	if "b'GetForegroundWindow'" in xk:
		point["b'GetForegroundWindow'"] = 1
	else:
		point["b'GetForegroundWindow'"] = 0

	if "b'GetFullPathNameA'" in xk:
		point["b'GetFullPathNameA'"] = 1
	else:
		point["b'GetFullPathNameA'"] = 0

	if "b'GetFullPathNameW'" in xk:
		point["b'GetFullPathNameW'"] = 1
	else:
		point["b'GetFullPathNameW'"] = 0

	if "b'GetGPOListA'" in xk:
		point["b'GetGPOListA'"] = 1
	else:
		point["b'GetGPOListA'"] = 0

	if "b'GetGUIThreadInfo'" in xk:
		point["b'GetGUIThreadInfo'"] = 1
	else:
		point["b'GetGUIThreadInfo'"] = 0

	if "b'GetGlyphOutlineA'" in xk:
		point["b'GetGlyphOutlineA'"] = 1
	else:
		point["b'GetGlyphOutlineA'"] = 0

	if "b'GetGlyphOutlineW'" in xk:
		point["b'GetGlyphOutlineW'"] = 1
	else:
		point["b'GetGlyphOutlineW'"] = 0

	if "b'GetGlyphOutlineWow'" in xk:
		point["b'GetGlyphOutlineWow'"] = 1
	else:
		point["b'GetGlyphOutlineWow'"] = 0

	if "b'GetGraphicsMode'" in xk:
		point["b'GetGraphicsMode'"] = 1
	else:
		point["b'GetGraphicsMode'"] = 0

	if "b'GetHGlobalFromStream'" in xk:
		point["b'GetHGlobalFromStream'"] = 1
	else:
		point["b'GetHGlobalFromStream'"] = 0

	if "b'GetHandleInformation'" in xk:
		point["b'GetHandleInformation'"] = 1
	else:
		point["b'GetHandleInformation'"] = 0

	if "b'GetICMProfileA'" in xk:
		point["b'GetICMProfileA'"] = 1
	else:
		point["b'GetICMProfileA'"] = 0

	if "b'GetIconInfo'" in xk:
		point["b'GetIconInfo'"] = 1
	else:
		point["b'GetIconInfo'"] = 0

	if "b'GetIfTable'" in xk:
		point["b'GetIfTable'"] = 1
	else:
		point["b'GetIfTable'"] = 0

	if "b'GetInputState'" in xk:
		point["b'GetInputState'"] = 1
	else:
		point["b'GetInputState'"] = 0

	if "b'GetIpAddrTable'" in xk:
		point["b'GetIpAddrTable'"] = 1
	else:
		point["b'GetIpAddrTable'"] = 0

	if "b'GetIpNetTable'" in xk:
		point["b'GetIpNetTable'"] = 1
	else:
		point["b'GetIpNetTable'"] = 0

	if "b'GetKBCodePage'" in xk:
		point["b'GetKBCodePage'"] = 1
	else:
		point["b'GetKBCodePage'"] = 0

	if "b'GetKernelObjectSecurity'" in xk:
		point["b'GetKernelObjectSecurity'"] = 1
	else:
		point["b'GetKernelObjectSecurity'"] = 0

	if "b'GetKerningPairsA'" in xk:
		point["b'GetKerningPairsA'"] = 1
	else:
		point["b'GetKerningPairsA'"] = 0

	if "b'GetKerningPairsW'" in xk:
		point["b'GetKerningPairsW'"] = 1
	else:
		point["b'GetKerningPairsW'"] = 0

	if "b'GetKeyNameTextA'" in xk:
		point["b'GetKeyNameTextA'"] = 1
	else:
		point["b'GetKeyNameTextA'"] = 0

	if "b'GetKeyNameTextW'" in xk:
		point["b'GetKeyNameTextW'"] = 1
	else:
		point["b'GetKeyNameTextW'"] = 0

	if "b'GetKeyState'" in xk:
		point["b'GetKeyState'"] = 1
	else:
		point["b'GetKeyState'"] = 0

	if "b'GetKeyboardLayout'" in xk:
		point["b'GetKeyboardLayout'"] = 1
	else:
		point["b'GetKeyboardLayout'"] = 0

	if "b'GetKeyboardLayoutList'" in xk:
		point["b'GetKeyboardLayoutList'"] = 1
	else:
		point["b'GetKeyboardLayoutList'"] = 0

	if "b'GetKeyboardLayoutNameA'" in xk:
		point["b'GetKeyboardLayoutNameA'"] = 1
	else:
		point["b'GetKeyboardLayoutNameA'"] = 0

	if "b'GetKeyboardLayoutNameW'" in xk:
		point["b'GetKeyboardLayoutNameW'"] = 1
	else:
		point["b'GetKeyboardLayoutNameW'"] = 0

	if "b'GetKeyboardState'" in xk:
		point["b'GetKeyboardState'"] = 1
	else:
		point["b'GetKeyboardState'"] = 0

	if "b'GetKeyboardType'" in xk:
		point["b'GetKeyboardType'"] = 1
	else:
		point["b'GetKeyboardType'"] = 0

	if "b'GetLastActivePopup'" in xk:
		point["b'GetLastActivePopup'"] = 1
	else:
		point["b'GetLastActivePopup'"] = 0

	if "b'GetLastError'" in xk:
		point["b'GetLastError'"] = 1
	else:
		point["b'GetLastError'"] = 0

	if "b'GetLastInputInfo'" in xk:
		point["b'GetLastInputInfo'"] = 1
	else:
		point["b'GetLastInputInfo'"] = 0

	if "b'GetLayout'" in xk:
		point["b'GetLayout'"] = 1
	else:
		point["b'GetLayout'"] = 0

	if "b'GetLinengthSid'" in xk:
		point["b'GetLinengthSid'"] = 1
	else:
		point["b'GetLinengthSid'"] = 0

	if "b'GetListBoxInfo'" in xk:
		point["b'GetListBoxInfo'"] = 1
	else:
		point["b'GetListBoxInfo'"] = 0

	if "b'GetLocalTime'" in xk:
		point["b'GetLocalTime'"] = 1
	else:
		point["b'GetLocalTime'"] = 0

	if "b'GetLocaleInfoA'" in xk:
		point["b'GetLocaleInfoA'"] = 1
	else:
		point["b'GetLocaleInfoA'"] = 0

	if "b'GetLocaleInfoW'" in xk:
		point["b'GetLocaleInfoW'"] = 1
	else:
		point["b'GetLocaleInfoW'"] = 0

	if "b'GetLocaleInfoEx'" in xk:
		point["b'GetLocaleInfoEx'"] = 1
	else:
		point["b'GetLocaleInfoEx'"] = 0

	if "b'GetLogicalDriveStringsA'" in xk:
		point["b'GetLogicalDriveStringsA'"] = 1
	else:
		point["b'GetLogicalDriveStringsA'"] = 0

	if "b'GetLogicalDriveStringsW'" in xk:
		point["b'GetLogicalDriveStringsW'"] = 1
	else:
		point["b'GetLogicalDriveStringsW'"] = 0

	if "b'GetLogicalDrives'" in xk:
		point["b'GetLogicalDrives'"] = 1
	else:
		point["b'GetLogicalDrives'"] = 0

	if "b'GetLogicalProcessorInformation'" in xk:
		point["b'GetLogicalProcessorInformation'"] = 1
	else:
		point["b'GetLogicalProcessorInformation'"] = 0

	if "b'GetLongPathNameA'" in xk:
		point["b'GetLongPathNameA'"] = 1
	else:
		point["b'GetLongPathNameA'"] = 0

	if "b'GetLongPathNameW'" in xk:
		point["b'GetLongPathNameW'"] = 1
	else:
		point["b'GetLongPathNameW'"] = 0

	if "b'GetMailslotInfo'" in xk:
		point["b'GetMailslotInfo'"] = 1
	else:
		point["b'GetMailslotInfo'"] = 0

	if "b'GetMapMode'" in xk:
		point["b'GetMapMode'"] = 1
	else:
		point["b'GetMapMode'"] = 0

	if "b'GetMenu'" in xk:
		point["b'GetMenu'"] = 1
	else:
		point["b'GetMenu'"] = 0

	if "b'GetMenuCheckMarkDimensions'" in xk:
		point["b'GetMenuCheckMarkDimensions'"] = 1
	else:
		point["b'GetMenuCheckMarkDimensions'"] = 0

	if "b'GetMenuContextHelpId'" in xk:
		point["b'GetMenuContextHelpId'"] = 1
	else:
		point["b'GetMenuContextHelpId'"] = 0

	if "b'GetMenuDefaultItem'" in xk:
		point["b'GetMenuDefaultItem'"] = 1
	else:
		point["b'GetMenuDefaultItem'"] = 0

	if "b'GetMenuItemCount'" in xk:
		point["b'GetMenuItemCount'"] = 1
	else:
		point["b'GetMenuItemCount'"] = 0

	if "b'GetMenuItemID'" in xk:
		point["b'GetMenuItemID'"] = 1
	else:
		point["b'GetMenuItemID'"] = 0

	if "b'GetMenuItemInfoA'" in xk:
		point["b'GetMenuItemInfoA'"] = 1
	else:
		point["b'GetMenuItemInfoA'"] = 0

	if "b'GetMenuItemInfoW'" in xk:
		point["b'GetMenuItemInfoW'"] = 1
	else:
		point["b'GetMenuItemInfoW'"] = 0

	if "b'GetMenuState'" in xk:
		point["b'GetMenuState'"] = 1
	else:
		point["b'GetMenuState'"] = 0

	if "b'GetMenuStringA'" in xk:
		point["b'GetMenuStringA'"] = 1
	else:
		point["b'GetMenuStringA'"] = 0

	if "b'GetMenuStringW'" in xk:
		point["b'GetMenuStringW'"] = 1
	else:
		point["b'GetMenuStringW'"] = 0

	if "b'GetMessageA'" in xk:
		point["b'GetMessageA'"] = 1
	else:
		point["b'GetMessageA'"] = 0

	if "b'GetMessageW'" in xk:
		point["b'GetMessageW'"] = 1
	else:
		point["b'GetMessageW'"] = 0

	if "b'GetMessageExtraInfo'" in xk:
		point["b'GetMessageExtraInfo'"] = 1
	else:
		point["b'GetMessageExtraInfo'"] = 0

	if "b'GetMessagePos'" in xk:
		point["b'GetMessagePos'"] = 1
	else:
		point["b'GetMessagePos'"] = 0

	if "b'GetMessageTime'" in xk:
		point["b'GetMessageTime'"] = 1
	else:
		point["b'GetMessageTime'"] = 0

	if "b'GetMetaRgn'" in xk:
		point["b'GetMetaRgn'"] = 1
	else:
		point["b'GetMetaRgn'"] = 0

	if "b'GetMiterLimit'" in xk:
		point["b'GetMiterLimit'"] = 1
	else:
		point["b'GetMiterLimit'"] = 0

	if "b'GetModuleBaseNameA'" in xk:
		point["b'GetModuleBaseNameA'"] = 1
	else:
		point["b'GetModuleBaseNameA'"] = 0

	if "b'GetModuleFileNameW'" in xk:
		point["b'GetModuleFileNameW'"] = 1
	else:
		point["b'GetModuleFileNameW'"] = 0

	if "b'GetModuleFileNameExA'" in xk:
		point["b'GetModuleFileNameExA'"] = 1
	else:
		point["b'GetModuleFileNameExA'"] = 0

	if "b'GetModuleFileNameExW'" in xk:
		point["b'GetModuleFileNameExW'"] = 1
	else:
		point["b'GetModuleFileNameExW'"] = 0

	if "b'GetModuleHandleA'" in xk:
		point["b'GetModuleHandleA'"] = 1
	else:
		point["b'GetModuleHandleA'"] = 0

	if "b'GetModuleHandleW'" in xk:
		point["b'GetModuleHandleW'"] = 1
	else:
		point["b'GetModuleHandleW'"] = 0

	if "b'GetModuleHandleExA'" in xk:
		point["b'GetModuleHandleExA'"] = 1
	else:
		point["b'GetModuleHandleExA'"] = 0

	if "b'GetModuleHandleExW'" in xk:
		point["b'GetModuleHandleExW'"] = 1
	else:
		point["b'GetModuleHandleExW'"] = 0

	if "b'GetModuleInformation'" in xk:
		point["b'GetModuleInformation'"] = 1
	else:
		point["b'GetModuleInformation'"] = 0

	if "b'GetMonitorInfoA'" in xk:
		point["b'GetMonitorInfoA'"] = 1
	else:
		point["b'GetMonitorInfoA'"] = 0

	if "b'GetMonitorInfoW'" in xk:
		point["b'GetMonitorInfoW'"] = 1
	else:
		point["b'GetMonitorInfoW'"] = 0

	if "b'GetMultipleTrusteeOperationA'" in xk:
		point["b'GetMultipleTrusteeOperationA'"] = 1
	else:
		point["b'GetMultipleTrusteeOperationA'"] = 0

	if "b'GetNativeSystemInfo'" in xk:
		point["b'GetNativeSystemInfo'"] = 1
	else:
		point["b'GetNativeSystemInfo'"] = 0

	if "b'GetNearestPaletteIndex'" in xk:
		point["b'GetNearestPaletteIndex'"] = 1
	else:
		point["b'GetNearestPaletteIndex'"] = 0

	if "b'GetNextDlgGroupItem'" in xk:
		point["b'GetNextDlgGroupItem'"] = 1
	else:
		point["b'GetNextDlgGroupItem'"] = 0

	if "b'GetNextDlgTabItem'" in xk:
		point["b'GetNextDlgTabItem'"] = 1
	else:
		point["b'GetNextDlgTabItem'"] = 0

	if "b'GetNumaHighestNodeNumber'" in xk:
		point["b'GetNumaHighestNodeNumber'"] = 1
	else:
		point["b'GetNumaHighestNodeNumber'"] = 0

	if "b'GetNumberFormatA'" in xk:
		point["b'GetNumberFormatA'"] = 1
	else:
		point["b'GetNumberFormatA'"] = 0

	if "b'GetNumberFormatW'" in xk:
		point["b'GetNumberFormatW'"] = 1
	else:
		point["b'GetNumberFormatW'"] = 0

	if "b'GetOEMCP'" in xk:
		point["b'GetOEMCP'"] = 1
	else:
		point["b'GetOEMCP'"] = 0

	if "b'GetObjectA'" in xk:
		point["b'GetObjectA'"] = 1
	else:
		point["b'GetObjectA'"] = 0

	if "b'GetObjectW'" in xk:
		point["b'GetObjectW'"] = 1
	else:
		point["b'GetObjectW'"] = 0

	if "b'GetObjectType'" in xk:
		point["b'GetObjectType'"] = 1
	else:
		point["b'GetObjectType'"] = 0

	if "b'GetOpenClipboardWindow'" in xk:
		point["b'GetOpenClipboardWindow'"] = 1
	else:
		point["b'GetOpenClipboardWindow'"] = 0

	if "b'GetOpenFileNameA'" in xk:
		point["b'GetOpenFileNameA'"] = 1
	else:
		point["b'GetOpenFileNameA'"] = 0

	if "b'GetOpenFileNameW'" in xk:
		point["b'GetOpenFileNameW'"] = 1
	else:
		point["b'GetOpenFileNameW'"] = 0

	if "b'GetOutlineTextMetricsA'" in xk:
		point["b'GetOutlineTextMetricsA'"] = 1
	else:
		point["b'GetOutlineTextMetricsA'"] = 0

	if "b'GetOverlappedResult'" in xk:
		point["b'GetOverlappedResult'"] = 1
	else:
		point["b'GetOverlappedResult'"] = 0

	if "b'GetPaletteEntries'" in xk:
		point["b'GetPaletteEntries'"] = 1
	else:
		point["b'GetPaletteEntries'"] = 0

	if "b'GetParent'" in xk:
		point["b'GetParent'"] = 1
	else:
		point["b'GetParent'"] = 0

	if "b'GetPerAdapterInfo'" in xk:
		point["b'GetPerAdapterInfo'"] = 1
	else:
		point["b'GetPerAdapterInfo'"] = 0

	if "b'GetPixel'" in xk:
		point["b'GetPixel'"] = 1
	else:
		point["b'GetPixel'"] = 0

	if "b'GetPixelFormat'" in xk:
		point["b'GetPixelFormat'"] = 1
	else:
		point["b'GetPixelFormat'"] = 0

	if "b'GetPriorityClipboardFormat'" in xk:
		point["b'GetPriorityClipboardFormat'"] = 1
	else:
		point["b'GetPriorityClipboardFormat'"] = 0

	if "b'GetPrivateProfileIntA'" in xk:
		point["b'GetPrivateProfileIntA'"] = 1
	else:
		point["b'GetPrivateProfileIntA'"] = 0

	if "b'GetPrivateProfileIntW'" in xk:
		point["b'GetPrivateProfileIntW'"] = 1
	else:
		point["b'GetPrivateProfileIntW'"] = 0

	if "b'GetPrivateProfileSectionW'" in xk:
		point["b'GetPrivateProfileSectionW'"] = 1
	else:
		point["b'GetPrivateProfileSectionW'"] = 0

	if "b'GetPrivateProfileSectionNamesW'" in xk:
		point["b'GetPrivateProfileSectionNamesW'"] = 1
	else:
		point["b'GetPrivateProfileSectionNamesW'"] = 0

	if "b'GetPrivateProfileStringA'" in xk:
		point["b'GetPrivateProfileStringA'"] = 1
	else:
		point["b'GetPrivateProfileStringA'"] = 0

	if "b'GetPrivateProfileStringW'" in xk:
		point["b'GetPrivateProfileStringW'"] = 1
	else:
		point["b'GetPrivateProfileStringW'"] = 0

	if "b'GetPrivateProfileStructA'" in xk:
		point["b'GetPrivateProfileStructA'"] = 1
	else:
		point["b'GetPrivateProfileStructA'"] = 0

	if "b'GetProcAddress'" in xk:
		point["b'GetProcAddress'"] = 1
	else:
		point["b'GetProcAddress'"] = 0

	if "b'GetProcessAffinityMask'" in xk:
		point["b'GetProcessAffinityMask'"] = 1
	else:
		point["b'GetProcessAffinityMask'"] = 0

	if "b'GetProcessHandleCount'" in xk:
		point["b'GetProcessHandleCount'"] = 1
	else:
		point["b'GetProcessHandleCount'"] = 0

	if "b'GetProcessHeap'" in xk:
		point["b'GetProcessHeap'"] = 1
	else:
		point["b'GetProcessHeap'"] = 0

	if "b'GetProcessHeaps'" in xk:
		point["b'GetProcessHeaps'"] = 1
	else:
		point["b'GetProcessHeaps'"] = 0

	if "b'GetProcessId'" in xk:
		point["b'GetProcessId'"] = 1
	else:
		point["b'GetProcessId'"] = 0

	if "b'GetProcessImageFileNameA'" in xk:
		point["b'GetProcessImageFileNameA'"] = 1
	else:
		point["b'GetProcessImageFileNameA'"] = 0

	if "b'GetProcessImageFileNameW'" in xk:
		point["b'GetProcessImageFileNameW'"] = 1
	else:
		point["b'GetProcessImageFileNameW'"] = 0

	if "b'GetProcessIoCounters'" in xk:
		point["b'GetProcessIoCounters'"] = 1
	else:
		point["b'GetProcessIoCounters'"] = 0

	if "b'GetProcessMemoryInfo'" in xk:
		point["b'GetProcessMemoryInfo'"] = 1
	else:
		point["b'GetProcessMemoryInfo'"] = 0

	if "b'GetProcessPriorityBoost'" in xk:
		point["b'GetProcessPriorityBoost'"] = 1
	else:
		point["b'GetProcessPriorityBoost'"] = 0

	if "b'GetProcessTimes'" in xk:
		point["b'GetProcessTimes'"] = 1
	else:
		point["b'GetProcessTimes'"] = 0

	if "b'GetProcessVersion'" in xk:
		point["b'GetProcessVersion'"] = 1
	else:
		point["b'GetProcessVersion'"] = 0

	if "b'GetProcessWindowStation'" in xk:
		point["b'GetProcessWindowStation'"] = 1
	else:
		point["b'GetProcessWindowStation'"] = 0

	if "b'GetProfileIntA'" in xk:
		point["b'GetProfileIntA'"] = 1
	else:
		point["b'GetProfileIntA'"] = 0

	if "b'GetProfileIntW'" in xk:
		point["b'GetProfileIntW'"] = 1
	else:
		point["b'GetProfileIntW'"] = 0

	if "b'GetProfileSectionA'" in xk:
		point["b'GetProfileSectionA'"] = 1
	else:
		point["b'GetProfileSectionA'"] = 0

	if "b'GetProfileStringA'" in xk:
		point["b'GetProfileStringA'"] = 1
	else:
		point["b'GetProfileStringA'"] = 0

	if "b'GetProfilesDirectoryA'" in xk:
		point["b'GetProfilesDirectoryA'"] = 1
	else:
		point["b'GetProfilesDirectoryA'"] = 0

	if "b'GetPropA'" in xk:
		point["b'GetPropA'"] = 1
	else:
		point["b'GetPropA'"] = 0

	if "b'GetPropW'" in xk:
		point["b'GetPropW'"] = 1
	else:
		point["b'GetPropW'"] = 0

	if "b'GetQueuedCompletionStatus'" in xk:
		point["b'GetQueuedCompletionStatus'"] = 1
	else:
		point["b'GetQueuedCompletionStatus'"] = 0

	if "b'GetRegionData'" in xk:
		point["b'GetRegionData'"] = 1
	else:
		point["b'GetRegionData'"] = 0

	if "b'GetRgnBox'" in xk:
		point["b'GetRgnBox'"] = 1
	else:
		point["b'GetRgnBox'"] = 0

	if "b'GetRunngObjectTable'" in xk:
		point["b'GetRunngObjectTable'"] = 1
	else:
		point["b'GetRunngObjectTable'"] = 0

	if "b'GetSaveFileNameA'" in xk:
		point["b'GetSaveFileNameA'"] = 1
	else:
		point["b'GetSaveFileNameA'"] = 0

	if "b'GetSaveFileNameW'" in xk:
		point["b'GetSaveFileNameW'"] = 1
	else:
		point["b'GetSaveFileNameW'"] = 0

	if "b'GetScrollBarInfo'" in xk:
		point["b'GetScrollBarInfo'"] = 1
	else:
		point["b'GetScrollBarInfo'"] = 0

	if "b'GetScrollInfo'" in xk:
		point["b'GetScrollInfo'"] = 1
	else:
		point["b'GetScrollInfo'"] = 0

	if "b'GetScrollPos'" in xk:
		point["b'GetScrollPos'"] = 1
	else:
		point["b'GetScrollPos'"] = 0

	if "b'GetScrollRange'" in xk:
		point["b'GetScrollRange'"] = 1
	else:
		point["b'GetScrollRange'"] = 0

	if "b'GetSecurityDescriptorControl'" in xk:
		point["b'GetSecurityDescriptorControl'"] = 1
	else:
		point["b'GetSecurityDescriptorControl'"] = 0

	if "b'GetSecurityDescriptorDacl'" in xk:
		point["b'GetSecurityDescriptorDacl'"] = 1
	else:
		point["b'GetSecurityDescriptorDacl'"] = 0

	if "b'GetSecurityDescriptorGroup'" in xk:
		point["b'GetSecurityDescriptorGroup'"] = 1
	else:
		point["b'GetSecurityDescriptorGroup'"] = 0

	if "b'GetSecurityDescriptorLinength'" in xk:
		point["b'GetSecurityDescriptorLinength'"] = 1
	else:
		point["b'GetSecurityDescriptorLinength'"] = 0

	if "b'GetSecurityDescriptorOwner'" in xk:
		point["b'GetSecurityDescriptorOwner'"] = 1
	else:
		point["b'GetSecurityDescriptorOwner'"] = 0

	if "b'GetSecurityDescriptorSacl'" in xk:
		point["b'GetSecurityDescriptorSacl'"] = 1
	else:
		point["b'GetSecurityDescriptorSacl'"] = 0

	if "b'GetServiceDisplayNameW'" in xk:
		point["b'GetServiceDisplayNameW'"] = 1
	else:
		point["b'GetServiceDisplayNameW'"] = 0

	if "b'GetShellWindow'" in xk:
		point["b'GetShellWindow'"] = 1
	else:
		point["b'GetShellWindow'"] = 0

	if "b'GetShortPathNameA'" in xk:
		point["b'GetShortPathNameA'"] = 1
	else:
		point["b'GetShortPathNameA'"] = 0

	if "b'GetShortPathNameW'" in xk:
		point["b'GetShortPathNameW'"] = 1
	else:
		point["b'GetShortPathNameW'"] = 0

	if "b'GetSidIdentifierAuthority'" in xk:
		point["b'GetSidIdentifierAuthority'"] = 1
	else:
		point["b'GetSidIdentifierAuthority'"] = 0

	if "b'GetSidLinengthRequired'" in xk:
		point["b'GetSidLinengthRequired'"] = 1
	else:
		point["b'GetSidLinengthRequired'"] = 0

	if "b'GetSidSubAuthority'" in xk:
		point["b'GetSidSubAuthority'"] = 1
	else:
		point["b'GetSidSubAuthority'"] = 0

	if "b'GetSidSubAuthorityCount'" in xk:
		point["b'GetSidSubAuthorityCount'"] = 1
	else:
		point["b'GetSidSubAuthorityCount'"] = 0

	if "b'GetStartupInfoA'" in xk:
		point["b'GetStartupInfoA'"] = 1
	else:
		point["b'GetStartupInfoA'"] = 0

	if "b'GetStartupInfoW'" in xk:
		point["b'GetStartupInfoW'"] = 1
	else:
		point["b'GetStartupInfoW'"] = 0

	if "b'GetStdHandle'" in xk:
		point["b'GetStdHandle'"] = 1
	else:
		point["b'GetStdHandle'"] = 0

	if "b'GetStockObject'" in xk:
		point["b'GetStockObject'"] = 1
	else:
		point["b'GetStockObject'"] = 0

	if "b'GetStretchBltMode'" in xk:
		point["b'GetStretchBltMode'"] = 1
	else:
		point["b'GetStretchBltMode'"] = 0

	if "b'GetStringTypeA'" in xk:
		point["b'GetStringTypeA'"] = 1
	else:
		point["b'GetStringTypeA'"] = 0

	if "b'GetStringTypeExA'" in xk:
		point["b'GetStringTypeExA'"] = 1
	else:
		point["b'GetStringTypeExA'"] = 0

	if "b'GetStringTypeW'" in xk:
		point["b'GetStringTypeW'"] = 1
	else:
		point["b'GetStringTypeW'"] = 0

	if "b'GetStringTypeExW'" in xk:
		point["b'GetStringTypeExW'"] = 1
	else:
		point["b'GetStringTypeExW'"] = 0

	if "b'GetSubMenu'" in xk:
		point["b'GetSubMenu'"] = 1
	else:
		point["b'GetSubMenu'"] = 0

	if "b'GetSysColor'" in xk:
		point["b'GetSysColor'"] = 1
	else:
		point["b'GetSysColor'"] = 0

	if "b'GetSysColorBrush'" in xk:
		point["b'GetSysColorBrush'"] = 1
	else:
		point["b'GetSysColorBrush'"] = 0

	if "b'GetSystemDefaultLCID'" in xk:
		point["b'GetSystemDefaultLCID'"] = 1
	else:
		point["b'GetSystemDefaultLCID'"] = 0

	if "b'GetSystemDefaultLangID'" in xk:
		point["b'GetSystemDefaultLangID'"] = 1
	else:
		point["b'GetSystemDefaultLangID'"] = 0

	if "b'GetSystemDefaultUILanguage'" in xk:
		point["b'GetSystemDefaultUILanguage'"] = 1
	else:
		point["b'GetSystemDefaultUILanguage'"] = 0

	if "b'GetSystemDirectoryA'" in xk:
		point["b'GetSystemDirectoryA'"] = 1
	else:
		point["b'GetSystemDirectoryA'"] = 0

	if "b'GetSystemDirectoryW'" in xk:
		point["b'GetSystemDirectoryW'"] = 1
	else:
		point["b'GetSystemDirectoryW'"] = 0

	if "b'GetSystemInfo'" in xk:
		point["b'GetSystemInfo'"] = 1
	else:
		point["b'GetSystemInfo'"] = 0

	if "b'GetSystemMenu'" in xk:
		point["b'GetSystemMenu'"] = 1
	else:
		point["b'GetSystemMenu'"] = 0

	if "b'GetSystemMetrics'" in xk:
		point["b'GetSystemMetrics'"] = 1
	else:
		point["b'GetSystemMetrics'"] = 0

	if "b'GetSystemPaletteEntries'" in xk:
		point["b'GetSystemPaletteEntries'"] = 1
	else:
		point["b'GetSystemPaletteEntries'"] = 0

	if "b'GetSystemPaletteUse'" in xk:
		point["b'GetSystemPaletteUse'"] = 1
	else:
		point["b'GetSystemPaletteUse'"] = 0

	if "b'GetSystemPowerStatus'" in xk:
		point["b'GetSystemPowerStatus'"] = 1
	else:
		point["b'GetSystemPowerStatus'"] = 0

	if "b'GetSystemTime'" in xk:
		point["b'GetSystemTime'"] = 1
	else:
		point["b'GetSystemTime'"] = 0

	if "b'GetSystemTimeAdjustment'" in xk:
		point["b'GetSystemTimeAdjustment'"] = 1
	else:
		point["b'GetSystemTimeAdjustment'"] = 0

	if "b'GetSystemTimeAsFileTime'" in xk:
		point["b'GetSystemTimeAsFileTime'"] = 1
	else:
		point["b'GetSystemTimeAsFileTime'"] = 0

	if "b'GetSystemTimes'" in xk:
		point["b'GetSystemTimes'"] = 1
	else:
		point["b'GetSystemTimes'"] = 0

	if "b'GetSystemWow64DirectoryA'" in xk:
		point["b'GetSystemWow64DirectoryA'"] = 1
	else:
		point["b'GetSystemWow64DirectoryA'"] = 0

	if "b'GetSystemWow64DirectoryW'" in xk:
		point["b'GetSystemWow64DirectoryW'"] = 1
	else:
		point["b'GetSystemWow64DirectoryW'"] = 0

	if "b'GetTapePosition'" in xk:
		point["b'GetTapePosition'"] = 1
	else:
		point["b'GetTapePosition'"] = 0

	if "b'GetTempFileNameA'" in xk:
		point["b'GetTempFileNameA'"] = 1
	else:
		point["b'GetTempFileNameA'"] = 0

	if "b'GetTempFileNameW'" in xk:
		point["b'GetTempFileNameW'"] = 1
	else:
		point["b'GetTempFileNameW'"] = 0

	if "b'GetTempPathA'" in xk:
		point["b'GetTempPathA'"] = 1
	else:
		point["b'GetTempPathA'"] = 0

	if "b'GetTempPathW'" in xk:
		point["b'GetTempPathW'"] = 1
	else:
		point["b'GetTempPathW'"] = 0

	if "b'GetTextAlign'" in xk:
		point["b'GetTextAlign'"] = 1
	else:
		point["b'GetTextAlign'"] = 0

	if "b'GetTextCharset'" in xk:
		point["b'GetTextCharset'"] = 1
	else:
		point["b'GetTextCharset'"] = 0

	if "b'GetTextCharsetInfo'" in xk:
		point["b'GetTextCharsetInfo'"] = 1
	else:
		point["b'GetTextCharsetInfo'"] = 0

	if "b'GetTextColor'" in xk:
		point["b'GetTextColor'"] = 1
	else:
		point["b'GetTextColor'"] = 0

	if "b'GetTextExtentPointA'" in xk:
		point["b'GetTextExtentPointA'"] = 1
	else:
		point["b'GetTextExtentPointA'"] = 0

	if "b'GetTextExtentPointW'" in xk:
		point["b'GetTextExtentPointW'"] = 1
	else:
		point["b'GetTextExtentPointW'"] = 0

	if "b'GetTextExtentPoint32A'" in xk:
		point["b'GetTextExtentPoint32A'"] = 1
	else:
		point["b'GetTextExtentPoint32A'"] = 0

	if "b'GetTextExtentPoint32W'" in xk:
		point["b'GetTextExtentPoint32W'"] = 1
	else:
		point["b'GetTextExtentPoint32W'"] = 0

	if "b'GetTextFaceA'" in xk:
		point["b'GetTextFaceA'"] = 1
	else:
		point["b'GetTextFaceA'"] = 0

	if "b'GetTextFaceW'" in xk:
		point["b'GetTextFaceW'"] = 1
	else:
		point["b'GetTextFaceW'"] = 0

	if "b'GetTextMetricsA'" in xk:
		point["b'GetTextMetricsA'"] = 1
	else:
		point["b'GetTextMetricsA'"] = 0

	if "b'GetTextMetricsW'" in xk:
		point["b'GetTextMetricsW'"] = 1
	else:
		point["b'GetTextMetricsW'"] = 0

	if "b'GetThemeColor'" in xk:
		point["b'GetThemeColor'"] = 1
	else:
		point["b'GetThemeColor'"] = 0

	if "b'GetThemeFont'" in xk:
		point["b'GetThemeFont'"] = 1
	else:
		point["b'GetThemeFont'"] = 0

	if "b'GetThemeInt'" in xk:
		point["b'GetThemeInt'"] = 1
	else:
		point["b'GetThemeInt'"] = 0

	if "b'GetThemePartSize'" in xk:
		point["b'GetThemePartSize'"] = 1
	else:
		point["b'GetThemePartSize'"] = 0

	if "b'GetThemeRect'" in xk:
		point["b'GetThemeRect'"] = 1
	else:
		point["b'GetThemeRect'"] = 0

	if "b'GetThemeString'" in xk:
		point["b'GetThemeString'"] = 1
	else:
		point["b'GetThemeString'"] = 0

	if "b'GetThemeSysColor'" in xk:
		point["b'GetThemeSysColor'"] = 1
	else:
		point["b'GetThemeSysColor'"] = 0

	if "b'GetThemeTextExtent'" in xk:
		point["b'GetThemeTextExtent'"] = 1
	else:
		point["b'GetThemeTextExtent'"] = 0

	if "b'GetThreadContext'" in xk:
		point["b'GetThreadContext'"] = 1
	else:
		point["b'GetThreadContext'"] = 0

	if "b'GetThreadDesktop'" in xk:
		point["b'GetThreadDesktop'"] = 1
	else:
		point["b'GetThreadDesktop'"] = 0

	if "b'GetThreadLocale'" in xk:
		point["b'GetThreadLocale'"] = 1
	else:
		point["b'GetThreadLocale'"] = 0

	if "b'GetThreadPriority'" in xk:
		point["b'GetThreadPriority'"] = 1
	else:
		point["b'GetThreadPriority'"] = 0

	if "b'GetThreadTimes'" in xk:
		point["b'GetThreadTimes'"] = 1
	else:
		point["b'GetThreadTimes'"] = 0

	if "b'GetTickCount'" in xk:
		point["b'GetTickCount'"] = 1
	else:
		point["b'GetTickCount'"] = 0

	if "b'GetTickCount64'" in xk:
		point["b'GetTickCount64'"] = 1
	else:
		point["b'GetTickCount64'"] = 0

	if "b'GetTimeFormatA'" in xk:
		point["b'GetTimeFormatA'"] = 1
	else:
		point["b'GetTimeFormatA'"] = 0

	if "b'GetTimeFormatW'" in xk:
		point["b'GetTimeFormatW'"] = 1
	else:
		point["b'GetTimeFormatW'"] = 0

	if "b'GetTimeFormatEx'" in xk:
		point["b'GetTimeFormatEx'"] = 1
	else:
		point["b'GetTimeFormatEx'"] = 0

	if "b'GetTimeZoneInformation'" in xk:
		point["b'GetTimeZoneInformation'"] = 1
	else:
		point["b'GetTimeZoneInformation'"] = 0

	if "b'GetTitleBarInfo'" in xk:
		point["b'GetTitleBarInfo'"] = 1
	else:
		point["b'GetTitleBarInfo'"] = 0

	if "b'GetTokenInformation'" in xk:
		point["b'GetTokenInformation'"] = 1
	else:
		point["b'GetTokenInformation'"] = 0

	if "b'GetTopWindow'" in xk:
		point["b'GetTopWindow'"] = 1
	else:
		point["b'GetTopWindow'"] = 0

	if "b'GetTraceEnableFlags'" in xk:
		point["b'GetTraceEnableFlags'"] = 1
	else:
		point["b'GetTraceEnableFlags'"] = 0

	if "b'GetTraceEnableLinevel'" in xk:
		point["b'GetTraceEnableLinevel'"] = 1
	else:
		point["b'GetTraceEnableLinevel'"] = 0

	if "b'GetTraceLoggerHandle'" in xk:
		point["b'GetTraceLoggerHandle'"] = 1
	else:
		point["b'GetTraceLoggerHandle'"] = 0

	if "b'GetUpdateRect'" in xk:
		point["b'GetUpdateRect'"] = 1
	else:
		point["b'GetUpdateRect'"] = 0

	if "b'GetUpdateRgn'" in xk:
		point["b'GetUpdateRgn'"] = 1
	else:
		point["b'GetUpdateRgn'"] = 0

	if "b'GetUserDefaultLCID'" in xk:
		point["b'GetUserDefaultLCID'"] = 1
	else:
		point["b'GetUserDefaultLCID'"] = 0

	if "b'GetUserDefaultLangID'" in xk:
		point["b'GetUserDefaultLangID'"] = 1
	else:
		point["b'GetUserDefaultLangID'"] = 0

	if "b'GetUserDefaultLocaleName'" in xk:
		point["b'GetUserDefaultLocaleName'"] = 1
	else:
		point["b'GetUserDefaultLocaleName'"] = 0

	if "b'GetUserDefaultUILanguage'" in xk:
		point["b'GetUserDefaultUILanguage'"] = 1
	else:
		point["b'GetUserDefaultUILanguage'"] = 0

	if "b'GetUserGeoID'" in xk:
		point["b'GetUserGeoID'"] = 1
	else:
		point["b'GetUserGeoID'"] = 0

	if "b'GetUserNameA'" in xk:
		point["b'GetUserNameA'"] = 1
	else:
		point["b'GetUserNameA'"] = 0

	if "b'GetUserNameW'" in xk:
		point["b'GetUserNameW'"] = 1
	else:
		point["b'GetUserNameW'"] = 0

	if "b'GetUserNameExA'" in xk:
		point["b'GetUserNameExA'"] = 1
	else:
		point["b'GetUserNameExA'"] = 0

	if "b'GetUserObjectInformationW'" in xk:
		point["b'GetUserObjectInformationW'"] = 1
	else:
		point["b'GetUserObjectInformationW'"] = 0

	if "b'GetUserObjectSecurity'" in xk:
		point["b'GetUserObjectSecurity'"] = 1
	else:
		point["b'GetUserObjectSecurity'"] = 0

	if "b'GetVersion'" in xk:
		point["b'GetVersion'"] = 1
	else:
		point["b'GetVersion'"] = 0

	if "b'GetVersionExA'" in xk:
		point["b'GetVersionExA'"] = 1
	else:
		point["b'GetVersionExA'"] = 0

	if "b'GetVersionExW'" in xk:
		point["b'GetVersionExW'"] = 1
	else:
		point["b'GetVersionExW'"] = 0

	if "b'GetViewportExtEx'" in xk:
		point["b'GetViewportExtEx'"] = 1
	else:
		point["b'GetViewportExtEx'"] = 0

	if "b'GetViewportOrgEx'" in xk:
		point["b'GetViewportOrgEx'"] = 1
	else:
		point["b'GetViewportOrgEx'"] = 0

	if "b'GetVolumeInformationA'" in xk:
		point["b'GetVolumeInformationA'"] = 1
	else:
		point["b'GetVolumeInformationA'"] = 0

	if "b'GetVolumeInformationW'" in xk:
		point["b'GetVolumeInformationW'"] = 1
	else:
		point["b'GetVolumeInformationW'"] = 0

	if "b'GetVolumePathNamesForVolumeNameA'" in xk:
		point["b'GetVolumePathNamesForVolumeNameA'"] = 1
	else:
		point["b'GetVolumePathNamesForVolumeNameA'"] = 0

	if "b'GetVolumePathNamesForVolumeNameW'" in xk:
		point["b'GetVolumePathNamesForVolumeNameW'"] = 1
	else:
		point["b'GetVolumePathNamesForVolumeNameW'"] = 0

	if "b'GetWMetaFileBits'" in xk:
		point["b'GetWMetaFileBits'"] = 1
	else:
		point["b'GetWMetaFileBits'"] = 0

	if "b'GetWindow'" in xk:
		point["b'GetWindow'"] = 1
	else:
		point["b'GetWindow'"] = 0

	if "b'GetWindowContextHelpId'" in xk:
		point["b'GetWindowContextHelpId'"] = 1
	else:
		point["b'GetWindowContextHelpId'"] = 0

	if "b'GetWindowDC'" in xk:
		point["b'GetWindowDC'"] = 1
	else:
		point["b'GetWindowDC'"] = 0

	if "b'GetWindowExtEx'" in xk:
		point["b'GetWindowExtEx'"] = 1
	else:
		point["b'GetWindowExtEx'"] = 0

	if "b'GetWindowInfoA'" in xk:
		point["b'GetWindowInfoA'"] = 1
	else:
		point["b'GetWindowInfoA'"] = 0

	if "b'GetWindowLongW'" in xk:
		point["b'GetWindowLongW'"] = 1
	else:
		point["b'GetWindowLongW'"] = 0

	if "b'GetWindowLong'" in xk:
		point["b'GetWindowLong'"] = 1
	else:
		point["b'GetWindowLong'"] = 0

	if "b'GetWindowModuleFileNameA'" in xk:
		point["b'GetWindowModuleFileNameA'"] = 1
	else:
		point["b'GetWindowModuleFileNameA'"] = 0

	if "b'GetWindowModuleFileNameW'" in xk:
		point["b'GetWindowModuleFileNameW'"] = 1
	else:
		point["b'GetWindowModuleFileNameW'"] = 0

	if "b'GetWindowOrgEx'" in xk:
		point["b'GetWindowOrgEx'"] = 1
	else:
		point["b'GetWindowOrgEx'"] = 0

	if "b'GetWindowPlacement'" in xk:
		point["b'GetWindowPlacement'"] = 1
	else:
		point["b'GetWindowPlacement'"] = 0

	if "b'GetWindowRect'" in xk:
		point["b'GetWindowRect'"] = 1
	else:
		point["b'GetWindowRect'"] = 0

	if "b'GetWindowRgn'" in xk:
		point["b'GetWindowRgn'"] = 1
	else:
		point["b'GetWindowRgn'"] = 0

	if "b'GetWindowTextA'" in xk:
		point["b'GetWindowTextA'"] = 1
	else:
		point["b'GetWindowTextA'"] = 0

	if "b'GetWindowTextW'" in xk:
		point["b'GetWindowTextW'"] = 1
	else:
		point["b'GetWindowTextW'"] = 0

	if "b'GetWindowTextLengthA'" in xk:
		point["b'GetWindowTextLengthA'"] = 1
	else:
		point["b'GetWindowTextLengthA'"] = 0

	if "b'GetWindowTextLengthW'" in xk:
		point["b'GetWindowTextLengthW'"] = 1
	else:
		point["b'GetWindowTextLengthW'"] = 0

	if "b'GetWindowTheme'" in xk:
		point["b'GetWindowTheme'"] = 1
	else:
		point["b'GetWindowTheme'"] = 0

	if "b'GetWindowThreadProcessId'" in xk:
		point["b'GetWindowThreadProcessId'"] = 1
	else:
		point["b'GetWindowThreadProcessId'"] = 0

	if "b'GetWindowWord'" in xk:
		point["b'GetWindowWord'"] = 1
	else:
		point["b'GetWindowWord'"] = 0

	if "b'GetWindowsAccountDomainSid'" in xk:
		point["b'GetWindowsAccountDomainSid'"] = 1
	else:
		point["b'GetWindowsAccountDomainSid'"] = 0

	if "b'GetWindowsDirectoryA'" in xk:
		point["b'GetWindowsDirectoryA'"] = 1
	else:
		point["b'GetWindowsDirectoryA'"] = 0

	if "b'GetWindowsDirectoryW'" in xk:
		point["b'GetWindowsDirectoryW'"] = 1
	else:
		point["b'GetWindowsDirectoryW'"] = 0

	if "b'GetWsChanges'" in xk:
		point["b'GetWsChanges'"] = 1
	else:
		point["b'GetWsChanges'"] = 0

	if "b'GlobalAddAtomA'" in xk:
		point["b'GlobalAddAtomA'"] = 1
	else:
		point["b'GlobalAddAtomA'"] = 0

	if "b'GlobalAddAtomW'" in xk:
		point["b'GlobalAddAtomW'"] = 1
	else:
		point["b'GlobalAddAtomW'"] = 0

	if "b'GlobalAlloc'" in xk:
		point["b'GlobalAlloc'"] = 1
	else:
		point["b'GlobalAlloc'"] = 0

	if "b'GlobalCompact'" in xk:
		point["b'GlobalCompact'"] = 1
	else:
		point["b'GlobalCompact'"] = 0

	if "b'GlobalDeleteAtom'" in xk:
		point["b'GlobalDeleteAtom'"] = 1
	else:
		point["b'GlobalDeleteAtom'"] = 0

	if "b'GlobalFindAtomA'" in xk:
		point["b'GlobalFindAtomA'"] = 1
	else:
		point["b'GlobalFindAtomA'"] = 0

	if "b'GlobalFindAtomW'" in xk:
		point["b'GlobalFindAtomW'"] = 1
	else:
		point["b'GlobalFindAtomW'"] = 0

	if "b'GlobalFix'" in xk:
		point["b'GlobalFix'"] = 1
	else:
		point["b'GlobalFix'"] = 0

	if "b'GlobalFlags'" in xk:
		point["b'GlobalFlags'"] = 1
	else:
		point["b'GlobalFlags'"] = 0

	if "b'GlobalFree'" in xk:
		point["b'GlobalFree'"] = 1
	else:
		point["b'GlobalFree'"] = 0

	if "b'GlobalGetAtomNameA'" in xk:
		point["b'GlobalGetAtomNameA'"] = 1
	else:
		point["b'GlobalGetAtomNameA'"] = 0

	if "b'GlobalGetAtomNameW'" in xk:
		point["b'GlobalGetAtomNameW'"] = 1
	else:
		point["b'GlobalGetAtomNameW'"] = 0

	if "b'GlobalHandle'" in xk:
		point["b'GlobalHandle'"] = 1
	else:
		point["b'GlobalHandle'"] = 0

	if "b'GlobalLock'" in xk:
		point["b'GlobalLock'"] = 1
	else:
		point["b'GlobalLock'"] = 0

	if "b'GlobalMemoryStatus'" in xk:
		point["b'GlobalMemoryStatus'"] = 1
	else:
		point["b'GlobalMemoryStatus'"] = 0

	if "b'GlobalMemoryStatusEx'" in xk:
		point["b'GlobalMemoryStatusEx'"] = 1
	else:
		point["b'GlobalMemoryStatusEx'"] = 0

	if "b'GlobalReAlloc'" in xk:
		point["b'GlobalReAlloc'"] = 1
	else:
		point["b'GlobalReAlloc'"] = 0

	if "b'GlobalSize'" in xk:
		point["b'GlobalSize'"] = 1
	else:
		point["b'GlobalSize'"] = 0

	if "b'GlobalUnWire'" in xk:
		point["b'GlobalUnWire'"] = 1
	else:
		point["b'GlobalUnWire'"] = 0

	if "b'GlobalUnfix'" in xk:
		point["b'GlobalUnfix'"] = 1
	else:
		point["b'GlobalUnfix'"] = 0

	if "b'GlobalUnlock'" in xk:
		point["b'GlobalUnlock'"] = 1
	else:
		point["b'GlobalUnlock'"] = 0

	if "b'GradientFill'" in xk:
		point["b'GradientFill'"] = 1
	else:
		point["b'GradientFill'"] = 0

	if "b'GrayStringA'" in xk:
		point["b'GrayStringA'"] = 1
	else:
		point["b'GrayStringA'"] = 0

	if "b'GrayStringW'" in xk:
		point["b'GrayStringW'"] = 1
	else:
		point["b'GrayStringW'"] = 0

	if "b'Heap32ListFirst'" in xk:
		point["b'Heap32ListFirst'"] = 1
	else:
		point["b'Heap32ListFirst'"] = 0

	if "b'HeapAlloc'" in xk:
		point["b'HeapAlloc'"] = 1
	else:
		point["b'HeapAlloc'"] = 0

	if "b'HeapCompact'" in xk:
		point["b'HeapCompact'"] = 1
	else:
		point["b'HeapCompact'"] = 0

	if "b'HeapCreate'" in xk:
		point["b'HeapCreate'"] = 1
	else:
		point["b'HeapCreate'"] = 0

	if "b'HeapDestroy'" in xk:
		point["b'HeapDestroy'"] = 1
	else:
		point["b'HeapDestroy'"] = 0

	if "b'HeapFree'" in xk:
		point["b'HeapFree'"] = 1
	else:
		point["b'HeapFree'"] = 0

	if "b'HeapLock'" in xk:
		point["b'HeapLock'"] = 1
	else:
		point["b'HeapLock'"] = 0

	if "b'HeapQueryInformation'" in xk:
		point["b'HeapQueryInformation'"] = 1
	else:
		point["b'HeapQueryInformation'"] = 0

	if "b'HeapReAlloc'" in xk:
		point["b'HeapReAlloc'"] = 1
	else:
		point["b'HeapReAlloc'"] = 0

	if "b'HeapSetInformation'" in xk:
		point["b'HeapSetInformation'"] = 1
	else:
		point["b'HeapSetInformation'"] = 0

	if "b'HeapSize'" in xk:
		point["b'HeapSize'"] = 1
	else:
		point["b'HeapSize'"] = 0

	if "b'HeapValidate'" in xk:
		point["b'HeapValidate'"] = 1
	else:
		point["b'HeapValidate'"] = 0

	if "b'HideCaret'" in xk:
		point["b'HideCaret'"] = 1
	else:
		point["b'HideCaret'"] = 0

	if "b'HiliteMenuItem'" in xk:
		point["b'HiliteMenuItem'"] = 1
	else:
		point["b'HiliteMenuItem'"] = 0

	if "b'HlinkGoBack'" in xk:
		point["b'HlinkGoBack'"] = 1
	else:
		point["b'HlinkGoBack'"] = 0

	if "b'HttpAddRequestHeadersA'" in xk:
		point["b'HttpAddRequestHeadersA'"] = 1
	else:
		point["b'HttpAddRequestHeadersA'"] = 0

	if "b'HttpEndRequestA'" in xk:
		point["b'HttpEndRequestA'"] = 1
	else:
		point["b'HttpEndRequestA'"] = 0

	if "b'HttpOpenRequestA'" in xk:
		point["b'HttpOpenRequestA'"] = 1
	else:
		point["b'HttpOpenRequestA'"] = 0

	if "b'HttpOpenRequestW'" in xk:
		point["b'HttpOpenRequestW'"] = 1
	else:
		point["b'HttpOpenRequestW'"] = 0

	if "b'HttpQueryInfoA'" in xk:
		point["b'HttpQueryInfoA'"] = 1
	else:
		point["b'HttpQueryInfoA'"] = 0

	if "b'HttpQueryInfoW'" in xk:
		point["b'HttpQueryInfoW'"] = 1
	else:
		point["b'HttpQueryInfoW'"] = 0

	if "b'HttpSendRequestA'" in xk:
		point["b'HttpSendRequestA'"] = 1
	else:
		point["b'HttpSendRequestA'"] = 0

	if "b'HttpSendRequestW'" in xk:
		point["b'HttpSendRequestW'"] = 1
	else:
		point["b'HttpSendRequestW'"] = 0

	if "b'HttpSendRequestExA'" in xk:
		point["b'HttpSendRequestExA'"] = 1
	else:
		point["b'HttpSendRequestExA'"] = 0

	if "b'ICClose'" in xk:
		point["b'ICClose'"] = 1
	else:
		point["b'ICClose'"] = 0

	if "b'ICCompressorFree'" in xk:
		point["b'ICCompressorFree'"] = 1
	else:
		point["b'ICCompressorFree'"] = 0

	if "b'ICOpen'" in xk:
		point["b'ICOpen'"] = 1
	else:
		point["b'ICOpen'"] = 0

	if "b'IIDFromString'" in xk:
		point["b'IIDFromString'"] = 1
	else:
		point["b'IIDFromString'"] = 0

	if "b'ILIsParent'" in xk:
		point["b'ILIsParent'"] = 1
	else:
		point["b'ILIsParent'"] = 0

	if "b'IMPGetIMEW'" in xk:
		point["b'IMPGetIMEW'"] = 1
	else:
		point["b'IMPGetIMEW'"] = 0

	if "b'IcmpCloseHandle'" in xk:
		point["b'IcmpCloseHandle'"] = 1
	else:
		point["b'IcmpCloseHandle'"] = 0

	if "b'IcmpCreateFile'" in xk:
		point["b'IcmpCreateFile'"] = 1
	else:
		point["b'IcmpCreateFile'"] = 0

	if "b'IcmpSendEcho'" in xk:
		point["b'IcmpSendEcho'"] = 1
	else:
		point["b'IcmpSendEcho'"] = 0

	if "b'ImageList_Add'" in xk:
		point["b'ImageList_Add'"] = 1
	else:
		point["b'ImageList_Add'"] = 0

	if "b'ImageList_AddMasked'" in xk:
		point["b'ImageList_AddMasked'"] = 1
	else:
		point["b'ImageList_AddMasked'"] = 0

	if "b'ImageList_BeginDrag'" in xk:
		point["b'ImageList_BeginDrag'"] = 1
	else:
		point["b'ImageList_BeginDrag'"] = 0

	if "b'ImageList_Create'" in xk:
		point["b'ImageList_Create'"] = 1
	else:
		point["b'ImageList_Create'"] = 0

	if "b'ImageList_Destroy'" in xk:
		point["b'ImageList_Destroy'"] = 1
	else:
		point["b'ImageList_Destroy'"] = 0

	if "b'ImageList_DragEnter'" in xk:
		point["b'ImageList_DragEnter'"] = 1
	else:
		point["b'ImageList_DragEnter'"] = 0

	if "b'ImageList_DragLeave'" in xk:
		point["b'ImageList_DragLeave'"] = 1
	else:
		point["b'ImageList_DragLeave'"] = 0

	if "b'ImageList_DragMove'" in xk:
		point["b'ImageList_DragMove'"] = 1
	else:
		point["b'ImageList_DragMove'"] = 0

	if "b'ImageList_DragShowNolock'" in xk:
		point["b'ImageList_DragShowNolock'"] = 1
	else:
		point["b'ImageList_DragShowNolock'"] = 0

	if "b'ImageList_Draw'" in xk:
		point["b'ImageList_Draw'"] = 1
	else:
		point["b'ImageList_Draw'"] = 0

	if "b'ImageList_DrawEx'" in xk:
		point["b'ImageList_DrawEx'"] = 1
	else:
		point["b'ImageList_DrawEx'"] = 0

	if "b'ImageList_EndDrag'" in xk:
		point["b'ImageList_EndDrag'"] = 1
	else:
		point["b'ImageList_EndDrag'"] = 0

	if "b'ImageList_GetBkColor'" in xk:
		point["b'ImageList_GetBkColor'"] = 1
	else:
		point["b'ImageList_GetBkColor'"] = 0

	if "b'ImageList_GetDragImage'" in xk:
		point["b'ImageList_GetDragImage'"] = 1
	else:
		point["b'ImageList_GetDragImage'"] = 0

	if "b'ImageList_GetIcon'" in xk:
		point["b'ImageList_GetIcon'"] = 1
	else:
		point["b'ImageList_GetIcon'"] = 0

	if "b'ImageList_GetIconSize'" in xk:
		point["b'ImageList_GetIconSize'"] = 1
	else:
		point["b'ImageList_GetIconSize'"] = 0

	if "b'ImageList_GetImageCount'" in xk:
		point["b'ImageList_GetImageCount'"] = 1
	else:
		point["b'ImageList_GetImageCount'"] = 0

	if "b'ImageList_LoadImageW'" in xk:
		point["b'ImageList_LoadImageW'"] = 1
	else:
		point["b'ImageList_LoadImageW'"] = 0

	if "b'ImageList_Read'" in xk:
		point["b'ImageList_Read'"] = 1
	else:
		point["b'ImageList_Read'"] = 0

	if "b'ImageList_Remove'" in xk:
		point["b'ImageList_Remove'"] = 1
	else:
		point["b'ImageList_Remove'"] = 0

	if "b'ImageList_Replace'" in xk:
		point["b'ImageList_Replace'"] = 1
	else:
		point["b'ImageList_Replace'"] = 0

	if "b'ImageList_ReplaceIcon'" in xk:
		point["b'ImageList_ReplaceIcon'"] = 1
	else:
		point["b'ImageList_ReplaceIcon'"] = 0

	if "b'ImageList_SetBkColor'" in xk:
		point["b'ImageList_SetBkColor'"] = 1
	else:
		point["b'ImageList_SetBkColor'"] = 0

	if "b'ImageList_SetDragCursorImage'" in xk:
		point["b'ImageList_SetDragCursorImage'"] = 1
	else:
		point["b'ImageList_SetDragCursorImage'"] = 0

	if "b'ImageList_SetIconSize'" in xk:
		point["b'ImageList_SetIconSize'"] = 1
	else:
		point["b'ImageList_SetIconSize'"] = 0

	if "b'ImageList_Write'" in xk:
		point["b'ImageList_Write'"] = 1
	else:
		point["b'ImageList_Write'"] = 0

	if "b'ImageNtHeader'" in xk:
		point["b'ImageNtHeader'"] = 1
	else:
		point["b'ImageNtHeader'"] = 0

	if "b'ImageRvaToSection'" in xk:
		point["b'ImageRvaToSection'"] = 1
	else:
		point["b'ImageRvaToSection'"] = 0

	if "b'ImageRvaToVa'" in xk:
		point["b'ImageRvaToVa'"] = 1
	else:
		point["b'ImageRvaToVa'"] = 0

	if "b'ImmAssociateContext'" in xk:
		point["b'ImmAssociateContext'"] = 1
	else:
		point["b'ImmAssociateContext'"] = 0

	if "b'ImmConfigureIMEA'" in xk:
		point["b'ImmConfigureIMEA'"] = 1
	else:
		point["b'ImmConfigureIMEA'"] = 0

	if "b'ImmCreateContext'" in xk:
		point["b'ImmCreateContext'"] = 1
	else:
		point["b'ImmCreateContext'"] = 0

	if "b'ImmDestroyContext'" in xk:
		point["b'ImmDestroyContext'"] = 1
	else:
		point["b'ImmDestroyContext'"] = 0

	if "b'ImmDisableIME'" in xk:
		point["b'ImmDisableIME'"] = 1
	else:
		point["b'ImmDisableIME'"] = 0

	if "b'ImmGetCandidateListCountA'" in xk:
		point["b'ImmGetCandidateListCountA'"] = 1
	else:
		point["b'ImmGetCandidateListCountA'"] = 0

	if "b'ImmGetCompositionStringA'" in xk:
		point["b'ImmGetCompositionStringA'"] = 1
	else:
		point["b'ImmGetCompositionStringA'"] = 0

	if "b'ImmGetContext'" in xk:
		point["b'ImmGetContext'"] = 1
	else:
		point["b'ImmGetContext'"] = 0

	if "b'ImmGetOpenStatus'" in xk:
		point["b'ImmGetOpenStatus'"] = 1
	else:
		point["b'ImmGetOpenStatus'"] = 0

	if "b'ImmGetProperty'" in xk:
		point["b'ImmGetProperty'"] = 1
	else:
		point["b'ImmGetProperty'"] = 0

	if "b'ImmInstallIMEA'" in xk:
		point["b'ImmInstallIMEA'"] = 1
	else:
		point["b'ImmInstallIMEA'"] = 0

	if "b'ImmNotifyIME'" in xk:
		point["b'ImmNotifyIME'"] = 1
	else:
		point["b'ImmNotifyIME'"] = 0

	if "b'ImmReleaseContext'" in xk:
		point["b'ImmReleaseContext'"] = 1
	else:
		point["b'ImmReleaseContext'"] = 0

	if "b'ImmSetConversionStatus'" in xk:
		point["b'ImmSetConversionStatus'"] = 1
	else:
		point["b'ImmSetConversionStatus'"] = 0

	if "b'ImmSetOpenStatus'" in xk:
		point["b'ImmSetOpenStatus'"] = 1
	else:
		point["b'ImmSetOpenStatus'"] = 0

	if "b'ImmSimulateHotKey'" in xk:
		point["b'ImmSimulateHotKey'"] = 1
	else:
		point["b'ImmSimulateHotKey'"] = 0

	if "b'ImpersonateLoggedOnUser'" in xk:
		point["b'ImpersonateLoggedOnUser'"] = 1
	else:
		point["b'ImpersonateLoggedOnUser'"] = 0

	if "b'InSendMessage'" in xk:
		point["b'InSendMessage'"] = 1
	else:
		point["b'InSendMessage'"] = 0

	if "b'InflateRect'" in xk:
		point["b'InflateRect'"] = 1
	else:
		point["b'InflateRect'"] = 0

	if "b'InitAtomTable'" in xk:
		point["b'InitAtomTable'"] = 1
	else:
		point["b'InitAtomTable'"] = 0

	if "b'InitCommonControls'" in xk:
		point["b'InitCommonControls'"] = 1
	else:
		point["b'InitCommonControls'"] = 0

	if "b'InitCommonControlsEx'" in xk:
		point["b'InitCommonControlsEx'"] = 1
	else:
		point["b'InitCommonControlsEx'"] = 0

	if "b'InitOnceExecuteOnce'" in xk:
		point["b'InitOnceExecuteOnce'"] = 1
	else:
		point["b'InitOnceExecuteOnce'"] = 0

	if "b'InitSafeBootMode'" in xk:
		point["b'InitSafeBootMode'"] = 1
	else:
		point["b'InitSafeBootMode'"] = 0

	if "b'InitSession'" in xk:
		point["b'InitSession'"] = 1
	else:
		point["b'InitSession'"] = 0

	if "b'InitializeAcl'" in xk:
		point["b'InitializeAcl'"] = 1
	else:
		point["b'InitializeAcl'"] = 0

	if "b'InitializeCriticalSection'" in xk:
		point["b'InitializeCriticalSection'"] = 1
	else:
		point["b'InitializeCriticalSection'"] = 0

	if "b'InitializeCriticalSectionAndSpinCount'" in xk:
		point["b'InitializeCriticalSectionAndSpinCount'"] = 1
	else:
		point["b'InitializeCriticalSectionAndSpinCount'"] = 0

	if "b'InitializeCriticalSectionEx'" in xk:
		point["b'InitializeCriticalSectionEx'"] = 1
	else:
		point["b'InitializeCriticalSectionEx'"] = 0

	if "b'InitializeSListHead'" in xk:
		point["b'InitializeSListHead'"] = 1
	else:
		point["b'InitializeSListHead'"] = 0

	if "b'InitializeSecurityDescriptor'" in xk:
		point["b'InitializeSecurityDescriptor'"] = 1
	else:
		point["b'InitializeSecurityDescriptor'"] = 0

	if "b'InitializeSid'" in xk:
		point["b'InitializeSid'"] = 1
	else:
		point["b'InitializeSid'"] = 0

	if "b'InitiateSystemShutdownA'" in xk:
		point["b'InitiateSystemShutdownA'"] = 1
	else:
		point["b'InitiateSystemShutdownA'"] = 0

	if "b'InitiateSystemShutdownW'" in xk:
		point["b'InitiateSystemShutdownW'"] = 1
	else:
		point["b'InitiateSystemShutdownW'"] = 0

	if "b'InitiateSystemShutdownExW'" in xk:
		point["b'InitiateSystemShutdownExW'"] = 1
	else:
		point["b'InitiateSystemShutdownExW'"] = 0

	if "b'InsertMenuA'" in xk:
		point["b'InsertMenuA'"] = 1
	else:
		point["b'InsertMenuA'"] = 0

	if "b'InsertMenuW'" in xk:
		point["b'InsertMenuW'"] = 1
	else:
		point["b'InsertMenuW'"] = 0

	if "b'InsertMenuItemA'" in xk:
		point["b'InsertMenuItemA'"] = 1
	else:
		point["b'InsertMenuItemA'"] = 0

	if "b'InsertMenuItemW'" in xk:
		point["b'InsertMenuItemW'"] = 1
	else:
		point["b'InsertMenuItemW'"] = 0

	if "b'InterlockedCompareExchange'" in xk:
		point["b'InterlockedCompareExchange'"] = 1
	else:
		point["b'InterlockedCompareExchange'"] = 0

	if "b'InterlockedDecrement'" in xk:
		point["b'InterlockedDecrement'"] = 1
	else:
		point["b'InterlockedDecrement'"] = 0

	if "b'InterlockedExchange'" in xk:
		point["b'InterlockedExchange'"] = 1
	else:
		point["b'InterlockedExchange'"] = 0

	if "b'InterlockedExchangeAdd'" in xk:
		point["b'InterlockedExchangeAdd'"] = 1
	else:
		point["b'InterlockedExchangeAdd'"] = 0

	if "b'InterlockedFlushSList'" in xk:
		point["b'InterlockedFlushSList'"] = 1
	else:
		point["b'InterlockedFlushSList'"] = 0

	if "b'InterlockedIncrement'" in xk:
		point["b'InterlockedIncrement'"] = 1
	else:
		point["b'InterlockedIncrement'"] = 0

	if "b'InterlockedPopEntrySList'" in xk:
		point["b'InterlockedPopEntrySList'"] = 1
	else:
		point["b'InterlockedPopEntrySList'"] = 0

	if "b'InterlockedPushEntrySList'" in xk:
		point["b'InterlockedPushEntrySList'"] = 1
	else:
		point["b'InterlockedPushEntrySList'"] = 0

	if "b'InternetCloseHandle'" in xk:
		point["b'InternetCloseHandle'"] = 1
	else:
		point["b'InternetCloseHandle'"] = 0

	if "b'InternetConnectA'" in xk:
		point["b'InternetConnectA'"] = 1
	else:
		point["b'InternetConnectA'"] = 0

	if "b'InternetConnectW'" in xk:
		point["b'InternetConnectW'"] = 1
	else:
		point["b'InternetConnectW'"] = 0

	if "b'InternetCrackUrlA'" in xk:
		point["b'InternetCrackUrlA'"] = 1
	else:
		point["b'InternetCrackUrlA'"] = 0

	if "b'InternetCrackUrlW'" in xk:
		point["b'InternetCrackUrlW'"] = 1
	else:
		point["b'InternetCrackUrlW'"] = 0

	if "b'InternetErrorDlg'" in xk:
		point["b'InternetErrorDlg'"] = 1
	else:
		point["b'InternetErrorDlg'"] = 0

	if "b'InternetFindNextFileA'" in xk:
		point["b'InternetFindNextFileA'"] = 1
	else:
		point["b'InternetFindNextFileA'"] = 0

	if "b'InternetGetConnectedState'" in xk:
		point["b'InternetGetConnectedState'"] = 1
	else:
		point["b'InternetGetConnectedState'"] = 0

	if "b'InternetGetConnectedStateExA'" in xk:
		point["b'InternetGetConnectedStateExA'"] = 1
	else:
		point["b'InternetGetConnectedStateExA'"] = 0

	if "b'InternetOpenA'" in xk:
		point["b'InternetOpenA'"] = 1
	else:
		point["b'InternetOpenA'"] = 0

	if "b'InternetOpenW'" in xk:
		point["b'InternetOpenW'"] = 1
	else:
		point["b'InternetOpenW'"] = 0

	if "b'InternetOpenUrlA'" in xk:
		point["b'InternetOpenUrlA'"] = 1
	else:
		point["b'InternetOpenUrlA'"] = 0

	if "b'InternetOpenUrlW'" in xk:
		point["b'InternetOpenUrlW'"] = 1
	else:
		point["b'InternetOpenUrlW'"] = 0

	if "b'InternetQueryDataAvailable'" in xk:
		point["b'InternetQueryDataAvailable'"] = 1
	else:
		point["b'InternetQueryDataAvailable'"] = 0

	if "b'InternetQueryOptionA'" in xk:
		point["b'InternetQueryOptionA'"] = 1
	else:
		point["b'InternetQueryOptionA'"] = 0

	if "b'InternetQueryOptionW'" in xk:
		point["b'InternetQueryOptionW'"] = 1
	else:
		point["b'InternetQueryOptionW'"] = 0

	if "b'InternetReadFile'" in xk:
		point["b'InternetReadFile'"] = 1
	else:
		point["b'InternetReadFile'"] = 0

	if "b'InternetSetCookieW'" in xk:
		point["b'InternetSetCookieW'"] = 1
	else:
		point["b'InternetSetCookieW'"] = 0

	if "b'InternetSetOptionA'" in xk:
		point["b'InternetSetOptionA'"] = 1
	else:
		point["b'InternetSetOptionA'"] = 0

	if "b'InternetSetOptionW'" in xk:
		point["b'InternetSetOptionW'"] = 1
	else:
		point["b'InternetSetOptionW'"] = 0

	if "b'InternetSetStatusCallbackA'" in xk:
		point["b'InternetSetStatusCallbackA'"] = 1
	else:
		point["b'InternetSetStatusCallbackA'"] = 0

	if "b'InternetTimeFromSystemTime'" in xk:
		point["b'InternetTimeFromSystemTime'"] = 1
	else:
		point["b'InternetTimeFromSystemTime'"] = 0

	if "b'InternetTimeToSystemTime'" in xk:
		point["b'InternetTimeToSystemTime'"] = 1
	else:
		point["b'InternetTimeToSystemTime'"] = 0

	if "b'InternetWriteFile'" in xk:
		point["b'InternetWriteFile'"] = 1
	else:
		point["b'InternetWriteFile'"] = 0

	if "b'IntersectClipRect'" in xk:
		point["b'IntersectClipRect'"] = 1
	else:
		point["b'IntersectClipRect'"] = 0

	if "b'IntersectRect'" in xk:
		point["b'IntersectRect'"] = 1
	else:
		point["b'IntersectRect'"] = 0

	if "b'InvalidateRect'" in xk:
		point["b'InvalidateRect'"] = 1
	else:
		point["b'InvalidateRect'"] = 0

	if "b'InvalidateRgn'" in xk:
		point["b'InvalidateRgn'"] = 1
	else:
		point["b'InvalidateRgn'"] = 0

	if "b'InvertRect'" in xk:
		point["b'InvertRect'"] = 1
	else:
		point["b'InvertRect'"] = 0

	if "b'IoAllocateWorkItem'" in xk:
		point["b'IoAllocateWorkItem'"] = 1
	else:
		point["b'IoAllocateWorkItem'"] = 0

	if "b'IoAttachDeviceToDeviceStack'" in xk:
		point["b'IoAttachDeviceToDeviceStack'"] = 1
	else:
		point["b'IoAttachDeviceToDeviceStack'"] = 0

	if "b'IoCreateDevice'" in xk:
		point["b'IoCreateDevice'"] = 1
	else:
		point["b'IoCreateDevice'"] = 0

	if "b'IoCreateSymbolicLink'" in xk:
		point["b'IoCreateSymbolicLink'"] = 1
	else:
		point["b'IoCreateSymbolicLink'"] = 0

	if "b'IoDeleteDevice'" in xk:
		point["b'IoDeleteDevice'"] = 1
	else:
		point["b'IoDeleteDevice'"] = 0

	if "b'IoDeleteSymbolicLink'" in xk:
		point["b'IoDeleteSymbolicLink'"] = 1
	else:
		point["b'IoDeleteSymbolicLink'"] = 0

	if "b'IoFreeWorkItem'" in xk:
		point["b'IoFreeWorkItem'"] = 1
	else:
		point["b'IoFreeWorkItem'"] = 0

	if "b'IoInitializeRemoveLockEx'" in xk:
		point["b'IoInitializeRemoveLockEx'"] = 1
	else:
		point["b'IoInitializeRemoveLockEx'"] = 0

	if "b'IoQueueWorkItem'" in xk:
		point["b'IoQueueWorkItem'"] = 1
	else:
		point["b'IoQueueWorkItem'"] = 0

	if "b'IoRegisterDriverReinitialization'" in xk:
		point["b'IoRegisterDriverReinitialization'"] = 1
	else:
		point["b'IoRegisterDriverReinitialization'"] = 0

	if "b'IofCompleteRequest'" in xk:
		point["b'IofCompleteRequest'"] = 1
	else:
		point["b'IofCompleteRequest'"] = 0

	if "b'IsAccelerator'" in xk:
		point["b'IsAccelerator'"] = 1
	else:
		point["b'IsAccelerator'"] = 0

	if "b'IsAppThemed'" in xk:
		point["b'IsAppThemed'"] = 1
	else:
		point["b'IsAppThemed'"] = 0

	if "b'IsBadCodePtr'" in xk:
		point["b'IsBadCodePtr'"] = 1
	else:
		point["b'IsBadCodePtr'"] = 0

	if "b'IsBadHugeReadPtr'" in xk:
		point["b'IsBadHugeReadPtr'"] = 1
	else:
		point["b'IsBadHugeReadPtr'"] = 0

	if "b'IsBadHugeWritePtr'" in xk:
		point["b'IsBadHugeWritePtr'"] = 1
	else:
		point["b'IsBadHugeWritePtr'"] = 0

	if "b'IsBadReadPtr'" in xk:
		point["b'IsBadReadPtr'"] = 1
	else:
		point["b'IsBadReadPtr'"] = 0

	if "b'IsBadStringPtrW'" in xk:
		point["b'IsBadStringPtrW'"] = 1
	else:
		point["b'IsBadStringPtrW'"] = 0

	if "b'IsBadWritePtr'" in xk:
		point["b'IsBadWritePtr'"] = 1
	else:
		point["b'IsBadWritePtr'"] = 0

	if "b'IsCharAlphaW'" in xk:
		point["b'IsCharAlphaW'"] = 1
	else:
		point["b'IsCharAlphaW'"] = 0

	if "b'IsCharAlphaNumericA'" in xk:
		point["b'IsCharAlphaNumericA'"] = 1
	else:
		point["b'IsCharAlphaNumericA'"] = 0

	if "b'IsCharAlphaNumericW'" in xk:
		point["b'IsCharAlphaNumericW'"] = 1
	else:
		point["b'IsCharAlphaNumericW'"] = 0

	if "b'IsCharLowerA'" in xk:
		point["b'IsCharLowerA'"] = 1
	else:
		point["b'IsCharLowerA'"] = 0

	if "b'IsCharLowerW'" in xk:
		point["b'IsCharLowerW'"] = 1
	else:
		point["b'IsCharLowerW'"] = 0

	if "b'IsCharUpperA'" in xk:
		point["b'IsCharUpperA'"] = 1
	else:
		point["b'IsCharUpperA'"] = 0

	if "b'IsCharUpperW'" in xk:
		point["b'IsCharUpperW'"] = 1
	else:
		point["b'IsCharUpperW'"] = 0

	if "b'IsChild'" in xk:
		point["b'IsChild'"] = 1
	else:
		point["b'IsChild'"] = 0

	if "b'IsClipboardFormatAvailable'" in xk:
		point["b'IsClipboardFormatAvailable'"] = 1
	else:
		point["b'IsClipboardFormatAvailable'"] = 0

	if "b'IsDBCSLeadByte'" in xk:
		point["b'IsDBCSLeadByte'"] = 1
	else:
		point["b'IsDBCSLeadByte'"] = 0

	if "b'IsDBCSLeadByteEx'" in xk:
		point["b'IsDBCSLeadByteEx'"] = 1
	else:
		point["b'IsDBCSLeadByteEx'"] = 0

	if "b'IsDebuggerPresent'" in xk:
		point["b'IsDebuggerPresent'"] = 1
	else:
		point["b'IsDebuggerPresent'"] = 0

	if "b'IsDialogMessageA'" in xk:
		point["b'IsDialogMessageA'"] = 1
	else:
		point["b'IsDialogMessageA'"] = 0

	if "b'IsDialogMessageW'" in xk:
		point["b'IsDialogMessageW'"] = 1
	else:
		point["b'IsDialogMessageW'"] = 0

	if "b'IsDlgButtonChecked'" in xk:
		point["b'IsDlgButtonChecked'"] = 1
	else:
		point["b'IsDlgButtonChecked'"] = 0

	if "b'IsEqualGUID'" in xk:
		point["b'IsEqualGUID'"] = 1
	else:
		point["b'IsEqualGUID'"] = 0

	if "b'IsIconic'" in xk:
		point["b'IsIconic'"] = 1
	else:
		point["b'IsIconic'"] = 0

	if "b'IsMenu'" in xk:
		point["b'IsMenu'"] = 1
	else:
		point["b'IsMenu'"] = 0

	if "b'IsProcessInJob'" in xk:
		point["b'IsProcessInJob'"] = 1
	else:
		point["b'IsProcessInJob'"] = 0

	if "b'IsProcessorFeaturePresent'" in xk:
		point["b'IsProcessorFeaturePresent'"] = 1
	else:
		point["b'IsProcessorFeaturePresent'"] = 0

	if "b'IsRectEmpty'" in xk:
		point["b'IsRectEmpty'"] = 1
	else:
		point["b'IsRectEmpty'"] = 0

	if "b'IsSystemResumeAutomatic'" in xk:
		point["b'IsSystemResumeAutomatic'"] = 1
	else:
		point["b'IsSystemResumeAutomatic'"] = 0

	if "b'IsTextUnicode'" in xk:
		point["b'IsTextUnicode'"] = 1
	else:
		point["b'IsTextUnicode'"] = 0

	if "b'IsThemeActive'" in xk:
		point["b'IsThemeActive'"] = 1
	else:
		point["b'IsThemeActive'"] = 0

	if "b'IsThemeBackgroundPartiallyTransparent'" in xk:
		point["b'IsThemeBackgroundPartiallyTransparent'"] = 1
	else:
		point["b'IsThemeBackgroundPartiallyTransparent'"] = 0

	if "b'IsValidCodePage'" in xk:
		point["b'IsValidCodePage'"] = 1
	else:
		point["b'IsValidCodePage'"] = 0

	if "b'IsValidLocale'" in xk:
		point["b'IsValidLocale'"] = 1
	else:
		point["b'IsValidLocale'"] = 0

	if "b'IsValidLocaleName'" in xk:
		point["b'IsValidLocaleName'"] = 1
	else:
		point["b'IsValidLocaleName'"] = 0

	if "b'IsValidSid'" in xk:
		point["b'IsValidSid'"] = 1
	else:
		point["b'IsValidSid'"] = 0

	if "b'IsWindow'" in xk:
		point["b'IsWindow'"] = 1
	else:
		point["b'IsWindow'"] = 0

	if "b'IsWindowEnabled'" in xk:
		point["b'IsWindowEnabled'"] = 1
	else:
		point["b'IsWindowEnabled'"] = 0

	if "b'IsWindowUnicode'" in xk:
		point["b'IsWindowUnicode'"] = 1
	else:
		point["b'IsWindowUnicode'"] = 0

	if "b'IsWindowVisible'" in xk:
		point["b'IsWindowVisible'"] = 1
	else:
		point["b'IsWindowVisible'"] = 0

	if "b'IsWow64Process'" in xk:
		point["b'IsWow64Process'"] = 1
	else:
		point["b'IsWow64Process'"] = 0

	if "b'IsZoomed'" in xk:
		point["b'IsZoomed'"] = 1
	else:
		point["b'IsZoomed'"] = 0

	if "b'KdDebuggerEnabled'" in xk:
		point["b'KdDebuggerEnabled'"] = 1
	else:
		point["b'KdDebuggerEnabled'"] = 0

	if "b'KeGetCurrentIrql'" in xk:
		point["b'KeGetCurrentIrql'"] = 1
	else:
		point["b'KeGetCurrentIrql'"] = 0

	if "b'KeGetCurrentThread'" in xk:
		point["b'KeGetCurrentThread'"] = 1
	else:
		point["b'KeGetCurrentThread'"] = 0

	if "b'KeInitializeMutex'" in xk:
		point["b'KeInitializeMutex'"] = 1
	else:
		point["b'KeInitializeMutex'"] = 0

	if "b'KeQueryPerformanceCounter'" in xk:
		point["b'KeQueryPerformanceCounter'"] = 1
	else:
		point["b'KeQueryPerformanceCounter'"] = 0

	if "b'KeQuerySystemTime'" in xk:
		point["b'KeQuerySystemTime'"] = 1
	else:
		point["b'KeQuerySystemTime'"] = 0

	if "b'KeReleaseMutex'" in xk:
		point["b'KeReleaseMutex'"] = 1
	else:
		point["b'KeReleaseMutex'"] = 0

	if "b'KeServiceDescriptorTable'" in xk:
		point["b'KeServiceDescriptorTable'"] = 1
	else:
		point["b'KeServiceDescriptorTable'"] = 0

	if "b'KeWaitForSingleObject'" in xk:
		point["b'KeWaitForSingleObject'"] = 1
	else:
		point["b'KeWaitForSingleObject'"] = 0

	if "b'KfAcquireSpinLock'" in xk:
		point["b'KfAcquireSpinLock'"] = 1
	else:
		point["b'KfAcquireSpinLock'"] = 0

	if "b'KfReleaseSpinLock'" in xk:
		point["b'KfReleaseSpinLock'"] = 1
	else:
		point["b'KfReleaseSpinLock'"] = 0

	if "b'KillTimer'" in xk:
		point["b'KillTimer'"] = 1
	else:
		point["b'KillTimer'"] = 0

	if "b'LCMapStringA'" in xk:
		point["b'LCMapStringA'"] = 1
	else:
		point["b'LCMapStringA'"] = 0

	if "b'LCMapStringW'" in xk:
		point["b'LCMapStringW'"] = 1
	else:
		point["b'LCMapStringW'"] = 0

	if "b'LCMapStringEx'" in xk:
		point["b'LCMapStringEx'"] = 1
	else:
		point["b'LCMapStringEx'"] = 0

	if "b'LPtoDP'" in xk:
		point["b'LPtoDP'"] = 1
	else:
		point["b'LPtoDP'"] = 0

	if "b'LZClose'" in xk:
		point["b'LZClose'"] = 1
	else:
		point["b'LZClose'"] = 0

	if "b'LZCopy'" in xk:
		point["b'LZCopy'"] = 1
	else:
		point["b'LZCopy'"] = 0

	if "b'LZOpenFileA'" in xk:
		point["b'LZOpenFileA'"] = 1
	else:
		point["b'LZOpenFileA'"] = 0

	if "b'LeaveCriticalSection'" in xk:
		point["b'LeaveCriticalSection'"] = 1
	else:
		point["b'LeaveCriticalSection'"] = 0

	if "b'LineTo'" in xk:
		point["b'LineTo'"] = 1
	else:
		point["b'LineTo'"] = 0

	if "b'LoadAcceleratorsA'" in xk:
		point["b'LoadAcceleratorsA'"] = 1
	else:
		point["b'LoadAcceleratorsA'"] = 0

	if "b'LoadAcceleratorsW'" in xk:
		point["b'LoadAcceleratorsW'"] = 1
	else:
		point["b'LoadAcceleratorsW'"] = 0

	if "b'LoadBitmapA'" in xk:
		point["b'LoadBitmapA'"] = 1
	else:
		point["b'LoadBitmapA'"] = 0

	if "b'LoadBitmapW'" in xk:
		point["b'LoadBitmapW'"] = 1
	else:
		point["b'LoadBitmapW'"] = 0

	if "b'LoadCursorA'" in xk:
		point["b'LoadCursorA'"] = 1
	else:
		point["b'LoadCursorA'"] = 0

	if "b'LoadCursorW'" in xk:
		point["b'LoadCursorW'"] = 1
	else:
		point["b'LoadCursorW'"] = 0

	if "b'LoadCursorFromFileA'" in xk:
		point["b'LoadCursorFromFileA'"] = 1
	else:
		point["b'LoadCursorFromFileA'"] = 0

	if "b'LoadCursorFromFileW'" in xk:
		point["b'LoadCursorFromFileW'"] = 1
	else:
		point["b'LoadCursorFromFileW'"] = 0

	if "b'LoadIconA'" in xk:
		point["b'LoadIconA'"] = 1
	else:
		point["b'LoadIconA'"] = 0

	if "b'LoadIconW'" in xk:
		point["b'LoadIconW'"] = 1
	else:
		point["b'LoadIconW'"] = 0

	if "b'LoadImageA'" in xk:
		point["b'LoadImageA'"] = 1
	else:
		point["b'LoadImageA'"] = 0

	if "b'LoadImageW'" in xk:
		point["b'LoadImageW'"] = 1
	else:
		point["b'LoadImageW'"] = 0

	if "b'LoadKeyboardLayoutA'" in xk:
		point["b'LoadKeyboardLayoutA'"] = 1
	else:
		point["b'LoadKeyboardLayoutA'"] = 0

	if "b'LoadLibraryA'" in xk:
		point["b'LoadLibraryA'"] = 1
	else:
		point["b'LoadLibraryA'"] = 0

	if "b'LoadLibraryW'" in xk:
		point["b'LoadLibraryW'"] = 1
	else:
		point["b'LoadLibraryW'"] = 0

	if "b'LoadLibraryExA'" in xk:
		point["b'LoadLibraryExA'"] = 1
	else:
		point["b'LoadLibraryExA'"] = 0

	if "b'LoadLibraryExW'" in xk:
		point["b'LoadLibraryExW'"] = 1
	else:
		point["b'LoadLibraryExW'"] = 0

	if "b'LoadMenuA'" in xk:
		point["b'LoadMenuA'"] = 1
	else:
		point["b'LoadMenuA'"] = 0

	if "b'LoadMenuW'" in xk:
		point["b'LoadMenuW'"] = 1
	else:
		point["b'LoadMenuW'"] = 0

	if "b'LoadResource'" in xk:
		point["b'LoadResource'"] = 1
	else:
		point["b'LoadResource'"] = 0

	if "b'LoadStringA'" in xk:
		point["b'LoadStringA'"] = 1
	else:
		point["b'LoadStringA'"] = 0

	if "b'LoadStringW'" in xk:
		point["b'LoadStringW'"] = 1
	else:
		point["b'LoadStringW'"] = 0

	if "b'LoadUserProfileW'" in xk:
		point["b'LoadUserProfileW'"] = 1
	else:
		point["b'LoadUserProfileW'"] = 0

	if "b'LocalAlloc'" in xk:
		point["b'LocalAlloc'"] = 1
	else:
		point["b'LocalAlloc'"] = 0

	if "b'LocalFileTimeToFileTime'" in xk:
		point["b'LocalFileTimeToFileTime'"] = 1
	else:
		point["b'LocalFileTimeToFileTime'"] = 0

	if "b'LocalFree'" in xk:
		point["b'LocalFree'"] = 1
	else:
		point["b'LocalFree'"] = 0

	if "b'LocalReAlloc'" in xk:
		point["b'LocalReAlloc'"] = 1
	else:
		point["b'LocalReAlloc'"] = 0

	if "b'LocalSize'" in xk:
		point["b'LocalSize'"] = 1
	else:
		point["b'LocalSize'"] = 0

	if "b'LockFile'" in xk:
		point["b'LockFile'"] = 1
	else:
		point["b'LockFile'"] = 0

	if "b'LockFileEx'" in xk:
		point["b'LockFileEx'"] = 1
	else:
		point["b'LockFileEx'"] = 0

	if "b'LockResource'" in xk:
		point["b'LockResource'"] = 1
	else:
		point["b'LockResource'"] = 0

	if "b'LockServiceDatabase'" in xk:
		point["b'LockServiceDatabase'"] = 1
	else:
		point["b'LockServiceDatabase'"] = 0

	if "b'LockSetForegroundWindow'" in xk:
		point["b'LockSetForegroundWindow'"] = 1
	else:
		point["b'LockSetForegroundWindow'"] = 0

	if "b'LockWindowUpdate'" in xk:
		point["b'LockWindowUpdate'"] = 1
	else:
		point["b'LockWindowUpdate'"] = 0

	if "b'LockWorkStation'" in xk:
		point["b'LockWorkStation'"] = 1
	else:
		point["b'LockWorkStation'"] = 0

	if "b'LogonUserW'" in xk:
		point["b'LogonUserW'"] = 1
	else:
		point["b'LogonUserW'"] = 0

	if "b'LookupAccountNameW'" in xk:
		point["b'LookupAccountNameW'"] = 1
	else:
		point["b'LookupAccountNameW'"] = 0

	if "b'LookupAccountSidA'" in xk:
		point["b'LookupAccountSidA'"] = 1
	else:
		point["b'LookupAccountSidA'"] = 0

	if "b'LookupAccountSidW'" in xk:
		point["b'LookupAccountSidW'"] = 1
	else:
		point["b'LookupAccountSidW'"] = 0

	if "b'LookupIconIdFromDirectoryEx'" in xk:
		point["b'LookupIconIdFromDirectoryEx'"] = 1
	else:
		point["b'LookupIconIdFromDirectoryEx'"] = 0

	if "b'LookupPrivilegeDisplayNameA'" in xk:
		point["b'LookupPrivilegeDisplayNameA'"] = 1
	else:
		point["b'LookupPrivilegeDisplayNameA'"] = 0

	if "b'LookupPrivilegeDisplayNameW'" in xk:
		point["b'LookupPrivilegeDisplayNameW'"] = 1
	else:
		point["b'LookupPrivilegeDisplayNameW'"] = 0

	if "b'LookupPrivilegeNameA'" in xk:
		point["b'LookupPrivilegeNameA'"] = 1
	else:
		point["b'LookupPrivilegeNameA'"] = 0

	if "b'LookupPrivilegeValueA'" in xk:
		point["b'LookupPrivilegeValueA'"] = 1
	else:
		point["b'LookupPrivilegeValueA'"] = 0

	if "b'LookupPrivilegeValueW'" in xk:
		point["b'LookupPrivilegeValueW'"] = 1
	else:
		point["b'LookupPrivilegeValueW'"] = 0

	if "b'LresultFromObject'" in xk:
		point["b'LresultFromObject'"] = 1
	else:
		point["b'LresultFromObject'"] = 0

	if "b'LsaLookupNames'" in xk:
		point["b'LsaLookupNames'"] = 1
	else:
		point["b'LsaLookupNames'"] = 0

	if "b'LsaQueryInformationPolicy'" in xk:
		point["b'LsaQueryInformationPolicy'"] = 1
	else:
		point["b'LsaQueryInformationPolicy'"] = 0

	if "b'MCIWndCreateW'" in xk:
		point["b'MCIWndCreateW'"] = 1
	else:
		point["b'MCIWndCreateW'"] = 0

	if "b'MakeAbsoluteSD'" in xk:
		point["b'MakeAbsoluteSD'"] = 1
	else:
		point["b'MakeAbsoluteSD'"] = 0

	if "b'MakeSelfRelativeSD'" in xk:
		point["b'MakeSelfRelativeSD'"] = 1
	else:
		point["b'MakeSelfRelativeSD'"] = 0

	if "b'MakeSureDirectoryPathExists'" in xk:
		point["b'MakeSureDirectoryPathExists'"] = 1
	else:
		point["b'MakeSureDirectoryPathExists'"] = 0

	if "b'MapDialogRect'" in xk:
		point["b'MapDialogRect'"] = 1
	else:
		point["b'MapDialogRect'"] = 0

	if "b'MapUserPhysicalPages'" in xk:
		point["b'MapUserPhysicalPages'"] = 1
	else:
		point["b'MapUserPhysicalPages'"] = 0

	if "b'MapUserPhysicalPagesScatter'" in xk:
		point["b'MapUserPhysicalPagesScatter'"] = 1
	else:
		point["b'MapUserPhysicalPagesScatter'"] = 0

	if "b'MapViewOfFile'" in xk:
		point["b'MapViewOfFile'"] = 1
	else:
		point["b'MapViewOfFile'"] = 0

	if "b'MapViewOfFileEx'" in xk:
		point["b'MapViewOfFileEx'"] = 1
	else:
		point["b'MapViewOfFileEx'"] = 0

	if "b'MapVirtualKeyA'" in xk:
		point["b'MapVirtualKeyA'"] = 1
	else:
		point["b'MapVirtualKeyA'"] = 0

	if "b'MapVirtualKeyW'" in xk:
		point["b'MapVirtualKeyW'"] = 1
	else:
		point["b'MapVirtualKeyW'"] = 0

	if "b'MapVirtualKeyExA'" in xk:
		point["b'MapVirtualKeyExA'"] = 1
	else:
		point["b'MapVirtualKeyExA'"] = 0

	if "b'MapVirtualKeyExW'" in xk:
		point["b'MapVirtualKeyExW'"] = 1
	else:
		point["b'MapVirtualKeyExW'"] = 0

	if "b'MapWindowPoints'" in xk:
		point["b'MapWindowPoints'"] = 1
	else:
		point["b'MapWindowPoints'"] = 0

	if "b'MaskBlt'" in xk:
		point["b'MaskBlt'"] = 1
	else:
		point["b'MaskBlt'"] = 0

	if "b'MessageBeep'" in xk:
		point["b'MessageBeep'"] = 1
	else:
		point["b'MessageBeep'"] = 0

	if "b'MessageBoxA'" in xk:
		point["b'MessageBoxA'"] = 1
	else:
		point["b'MessageBoxA'"] = 0

	if "b'MessageBoxW'" in xk:
		point["b'MessageBoxW'"] = 1
	else:
		point["b'MessageBoxW'"] = 0

	if "b'MessageBoxIndirectA'" in xk:
		point["b'MessageBoxIndirectA'"] = 1
	else:
		point["b'MessageBoxIndirectA'"] = 0

	if "b'MessageBoxIndirectW'" in xk:
		point["b'MessageBoxIndirectW'"] = 1
	else:
		point["b'MessageBoxIndirectW'"] = 0

	if "b'MkParseDisplayName'" in xk:
		point["b'MkParseDisplayName'"] = 1
	else:
		point["b'MkParseDisplayName'"] = 0

	if "b'MmGetPhysicalAddress'" in xk:
		point["b'MmGetPhysicalAddress'"] = 1
	else:
		point["b'MmGetPhysicalAddress'"] = 0

	if "b'MmGetSystemRoutineAddress'" in xk:
		point["b'MmGetSystemRoutineAddress'"] = 1
	else:
		point["b'MmGetSystemRoutineAddress'"] = 0

	if "b'MmMapIoSpace'" in xk:
		point["b'MmMapIoSpace'"] = 1
	else:
		point["b'MmMapIoSpace'"] = 0

	if "b'MmUnmapIoSpace'" in xk:
		point["b'MmUnmapIoSpace'"] = 1
	else:
		point["b'MmUnmapIoSpace'"] = 0

	if "b'ModifyMenuA'" in xk:
		point["b'ModifyMenuA'"] = 1
	else:
		point["b'ModifyMenuA'"] = 0

	if "b'ModifyMenuW'" in xk:
		point["b'ModifyMenuW'"] = 1
	else:
		point["b'ModifyMenuW'"] = 0

	if "b'Module32FirstW'" in xk:
		point["b'Module32FirstW'"] = 1
	else:
		point["b'Module32FirstW'"] = 0

	if "b'Module32NextW'" in xk:
		point["b'Module32NextW'"] = 1
	else:
		point["b'Module32NextW'"] = 0

	if "b'MonitorFromPoint'" in xk:
		point["b'MonitorFromPoint'"] = 1
	else:
		point["b'MonitorFromPoint'"] = 0

	if "b'MonitorFromRect'" in xk:
		point["b'MonitorFromRect'"] = 1
	else:
		point["b'MonitorFromRect'"] = 0

	if "b'MonitorFromWindow'" in xk:
		point["b'MonitorFromWindow'"] = 1
	else:
		point["b'MonitorFromWindow'"] = 0

	if "b'MoveFileA'" in xk:
		point["b'MoveFileA'"] = 1
	else:
		point["b'MoveFileA'"] = 0

	if "b'MoveFileW'" in xk:
		point["b'MoveFileW'"] = 1
	else:
		point["b'MoveFileW'"] = 0

	if "b'MoveFileExA'" in xk:
		point["b'MoveFileExA'"] = 1
	else:
		point["b'MoveFileExA'"] = 0

	if "b'MoveFileExW'" in xk:
		point["b'MoveFileExW'"] = 1
	else:
		point["b'MoveFileExW'"] = 0

	if "b'MoveFileWithProgressA'" in xk:
		point["b'MoveFileWithProgressA'"] = 1
	else:
		point["b'MoveFileWithProgressA'"] = 0

	if "b'MoveFileWithProgressW'" in xk:
		point["b'MoveFileWithProgressW'"] = 1
	else:
		point["b'MoveFileWithProgressW'"] = 0

	if "b'MoveToEx'" in xk:
		point["b'MoveToEx'"] = 1
	else:
		point["b'MoveToEx'"] = 0

	if "b'MoveWindow'" in xk:
		point["b'MoveWindow'"] = 1
	else:
		point["b'MoveWindow'"] = 0

	if "b'MsgWaitForMultipleObjects'" in xk:
		point["b'MsgWaitForMultipleObjects'"] = 1
	else:
		point["b'MsgWaitForMultipleObjects'"] = 0

	if "b'MsgWaitForMultipleObjectsEx'" in xk:
		point["b'MsgWaitForMultipleObjectsEx'"] = 1
	else:
		point["b'MsgWaitForMultipleObjectsEx'"] = 0

	if "b'MulDiv'" in xk:
		point["b'MulDiv'"] = 1
	else:
		point["b'MulDiv'"] = 0

	if "b'MultiByteToWideChar'" in xk:
		point["b'MultiByteToWideChar'"] = 1
	else:
		point["b'MultiByteToWideChar'"] = 0

	if "b'NDdeShareAddA'" in xk:
		point["b'NDdeShareAddA'"] = 1
	else:
		point["b'NDdeShareAddA'"] = 0

	if "b'NDdeShareDelA'" in xk:
		point["b'NDdeShareDelA'"] = 1
	else:
		point["b'NDdeShareDelA'"] = 0

	if "b'NDdeShareGetInfoA'" in xk:
		point["b'NDdeShareGetInfoA'"] = 1
	else:
		point["b'NDdeShareGetInfoA'"] = 0

	if "b'NdrClientCall2'" in xk:
		point["b'NdrClientCall2'"] = 1
	else:
		point["b'NdrClientCall2'"] = 0

	if "b'NetApiBufferFree'" in xk:
		point["b'NetApiBufferFree'"] = 1
	else:
		point["b'NetApiBufferFree'"] = 0

	if "b'NetAuditClear'" in xk:
		point["b'NetAuditClear'"] = 1
	else:
		point["b'NetAuditClear'"] = 0

	if "b'NetRemoteTOD'" in xk:
		point["b'NetRemoteTOD'"] = 1
	else:
		point["b'NetRemoteTOD'"] = 0

	if "b'NetScheduleJobAdd'" in xk:
		point["b'NetScheduleJobAdd'"] = 1
	else:
		point["b'NetScheduleJobAdd'"] = 0

	if "b'NetServerEnum'" in xk:
		point["b'NetServerEnum'"] = 1
	else:
		point["b'NetServerEnum'"] = 0

	if "b'NetServerGetInfo'" in xk:
		point["b'NetServerGetInfo'"] = 1
	else:
		point["b'NetServerGetInfo'"] = 0

	if "b'NetShareEnum'" in xk:
		point["b'NetShareEnum'"] = 1
	else:
		point["b'NetShareEnum'"] = 0

	if "b'NetShareGetInfo'" in xk:
		point["b'NetShareGetInfo'"] = 1
	else:
		point["b'NetShareGetInfo'"] = 0

	if "b'NetUserEnum'" in xk:
		point["b'NetUserEnum'"] = 1
	else:
		point["b'NetUserEnum'"] = 0

	if "b'NetUserModalsGet'" in xk:
		point["b'NetUserModalsGet'"] = 1
	else:
		point["b'NetUserModalsGet'"] = 0

	if "b'NetWkstaGetInfo'" in xk:
		point["b'NetWkstaGetInfo'"] = 1
	else:
		point["b'NetWkstaGetInfo'"] = 0

	if "b'NetWkstaUserGetInfo'" in xk:
		point["b'NetWkstaUserGetInfo'"] = 1
	else:
		point["b'NetWkstaUserGetInfo'"] = 0

	if "b'Netbios'" in xk:
		point["b'Netbios'"] = 1
	else:
		point["b'Netbios'"] = 0

	if "b'NotifyBootConfigStatus'" in xk:
		point["b'NotifyBootConfigStatus'"] = 1
	else:
		point["b'NotifyBootConfigStatus'"] = 0

	if "b'NotifyWinEvent'" in xk:
		point["b'NotifyWinEvent'"] = 1
	else:
		point["b'NotifyWinEvent'"] = 0

	if "b'NtBuildNumber'" in xk:
		point["b'NtBuildNumber'"] = 1
	else:
		point["b'NtBuildNumber'"] = 0

	if "b'NtClose'" in xk:
		point["b'NtClose'"] = 1
	else:
		point["b'NtClose'"] = 0

	if "b'NtCreateSection'" in xk:
		point["b'NtCreateSection'"] = 1
	else:
		point["b'NtCreateSection'"] = 0

	if "b'NtMapViewOfSection'" in xk:
		point["b'NtMapViewOfSection'"] = 1
	else:
		point["b'NtMapViewOfSection'"] = 0

	if "b'NtQueryInformationProcess'" in xk:
		point["b'NtQueryInformationProcess'"] = 1
	else:
		point["b'NtQueryInformationProcess'"] = 0

	if "b'NtQueryOpenSubKeys'" in xk:
		point["b'NtQueryOpenSubKeys'"] = 1
	else:
		point["b'NtQueryOpenSubKeys'"] = 0

	if "b'NtQuerySystemInformation'" in xk:
		point["b'NtQuerySystemInformation'"] = 1
	else:
		point["b'NtQuerySystemInformation'"] = 0

	if "b'NtQueryVirtualMemory'" in xk:
		point["b'NtQueryVirtualMemory'"] = 1
	else:
		point["b'NtQueryVirtualMemory'"] = 0

	if "b'NtReadFile'" in xk:
		point["b'NtReadFile'"] = 1
	else:
		point["b'NtReadFile'"] = 0

	if "b'NtReplyPort'" in xk:
		point["b'NtReplyPort'"] = 1
	else:
		point["b'NtReplyPort'"] = 0

	if "b'NtSetVolumeInformationFile'" in xk:
		point["b'NtSetVolumeInformationFile'"] = 1
	else:
		point["b'NtSetVolumeInformationFile'"] = 0

	if "b'NtUnmapViewOfSection'" in xk:
		point["b'NtUnmapViewOfSection'"] = 1
	else:
		point["b'NtUnmapViewOfSection'"] = 0

	if "b'NtYieldExecution'" in xk:
		point["b'NtYieldExecution'"] = 1
	else:
		point["b'NtYieldExecution'"] = 0

	if "b'ObOpenObjectByPointer'" in xk:
		point["b'ObOpenObjectByPointer'"] = 1
	else:
		point["b'ObOpenObjectByPointer'"] = 0

	if "b'ObfDereferenceObject'" in xk:
		point["b'ObfDereferenceObject'"] = 1
	else:
		point["b'ObfDereferenceObject'"] = 0

	if "b'OemKeyScan'" in xk:
		point["b'OemKeyScan'"] = 1
	else:
		point["b'OemKeyScan'"] = 0

	if "b'OemToCharA'" in xk:
		point["b'OemToCharA'"] = 1
	else:
		point["b'OemToCharA'"] = 0

	if "b'OemToCharBuffA'" in xk:
		point["b'OemToCharBuffA'"] = 1
	else:
		point["b'OemToCharBuffA'"] = 0

	if "b'OffsetClipRgn'" in xk:
		point["b'OffsetClipRgn'"] = 1
	else:
		point["b'OffsetClipRgn'"] = 0

	if "b'OffsetRect'" in xk:
		point["b'OffsetRect'"] = 1
	else:
		point["b'OffsetRect'"] = 0

	if "b'OffsetRgn'" in xk:
		point["b'OffsetRgn'"] = 1
	else:
		point["b'OffsetRgn'"] = 0

	if "b'OffsetViewportOrgEx'" in xk:
		point["b'OffsetViewportOrgEx'"] = 1
	else:
		point["b'OffsetViewportOrgEx'"] = 0

	if "b'OffsetWindowOrgEx'" in xk:
		point["b'OffsetWindowOrgEx'"] = 1
	else:
		point["b'OffsetWindowOrgEx'"] = 0

	if "b'OleCreateMenuDescriptor'" in xk:
		point["b'OleCreateMenuDescriptor'"] = 1
	else:
		point["b'OleCreateMenuDescriptor'"] = 0

	if "b'OleDestroyMenuDescriptor'" in xk:
		point["b'OleDestroyMenuDescriptor'"] = 1
	else:
		point["b'OleDestroyMenuDescriptor'"] = 0

	if "b'OleDuplicateData'" in xk:
		point["b'OleDuplicateData'"] = 1
	else:
		point["b'OleDuplicateData'"] = 0

	if "b'OleFlushClipboard'" in xk:
		point["b'OleFlushClipboard'"] = 1
	else:
		point["b'OleFlushClipboard'"] = 0

	if "b'OleGetClipboard'" in xk:
		point["b'OleGetClipboard'"] = 1
	else:
		point["b'OleGetClipboard'"] = 0

	if "b'OleInitialize'" in xk:
		point["b'OleInitialize'"] = 1
	else:
		point["b'OleInitialize'"] = 0

	if "b'OleIsCurrentClipboard'" in xk:
		point["b'OleIsCurrentClipboard'"] = 1
	else:
		point["b'OleIsCurrentClipboard'"] = 0

	if "b'OleLockRunning'" in xk:
		point["b'OleLockRunning'"] = 1
	else:
		point["b'OleLockRunning'"] = 0

	if "b'OleRun'" in xk:
		point["b'OleRun'"] = 1
	else:
		point["b'OleRun'"] = 0

	if "b'OleSetContainedObject'" in xk:
		point["b'OleSetContainedObject'"] = 1
	else:
		point["b'OleSetContainedObject'"] = 0

	if "b'OleSetMenuDescriptor'" in xk:
		point["b'OleSetMenuDescriptor'"] = 1
	else:
		point["b'OleSetMenuDescriptor'"] = 0

	if "b'OleTranslateAccelerator'" in xk:
		point["b'OleTranslateAccelerator'"] = 1
	else:
		point["b'OleTranslateAccelerator'"] = 0

	if "b'OleUIBusyW'" in xk:
		point["b'OleUIBusyW'"] = 1
	else:
		point["b'OleUIBusyW'"] = 0

	if "b'OleUninitialize'" in xk:
		point["b'OleUninitialize'"] = 1
	else:
		point["b'OleUninitialize'"] = 0

	if "b'OpenClipboard'" in xk:
		point["b'OpenClipboard'"] = 1
	else:
		point["b'OpenClipboard'"] = 0

	if "b'OpenDesktopW'" in xk:
		point["b'OpenDesktopW'"] = 1
	else:
		point["b'OpenDesktopW'"] = 0

	if "b'OpenEncryptedFileRawW'" in xk:
		point["b'OpenEncryptedFileRawW'"] = 1
	else:
		point["b'OpenEncryptedFileRawW'"] = 0

	if "b'OpenEventA'" in xk:
		point["b'OpenEventA'"] = 1
	else:
		point["b'OpenEventA'"] = 0

	if "b'OpenEventW'" in xk:
		point["b'OpenEventW'"] = 1
	else:
		point["b'OpenEventW'"] = 0

	if "b'OpenEventLogA'" in xk:
		point["b'OpenEventLogA'"] = 1
	else:
		point["b'OpenEventLogA'"] = 0

	if "b'OpenEventLogW'" in xk:
		point["b'OpenEventLogW'"] = 1
	else:
		point["b'OpenEventLogW'"] = 0

	if "b'OpenFile'" in xk:
		point["b'OpenFile'"] = 1
	else:
		point["b'OpenFile'"] = 0

	if "b'OpenFileMappingA'" in xk:
		point["b'OpenFileMappingA'"] = 1
	else:
		point["b'OpenFileMappingA'"] = 0

	if "b'OpenFileMappingW'" in xk:
		point["b'OpenFileMappingW'"] = 1
	else:
		point["b'OpenFileMappingW'"] = 0

	if "b'OpenIcon'" in xk:
		point["b'OpenIcon'"] = 1
	else:
		point["b'OpenIcon'"] = 0

	if "b'OpenMutexA'" in xk:
		point["b'OpenMutexA'"] = 1
	else:
		point["b'OpenMutexA'"] = 0

	if "b'OpenMutexW'" in xk:
		point["b'OpenMutexW'"] = 1
	else:
		point["b'OpenMutexW'"] = 0

	if "b'OpenPrinterA'" in xk:
		point["b'OpenPrinterA'"] = 1
	else:
		point["b'OpenPrinterA'"] = 0

	if "b'OpenPrinterW'" in xk:
		point["b'OpenPrinterW'"] = 1
	else:
		point["b'OpenPrinterW'"] = 0

	if "b'OpenProcess'" in xk:
		point["b'OpenProcess'"] = 1
	else:
		point["b'OpenProcess'"] = 0

	if "b'OpenProcessToken'" in xk:
		point["b'OpenProcessToken'"] = 1
	else:
		point["b'OpenProcessToken'"] = 0

	if "b'OpenSCManagerA'" in xk:
		point["b'OpenSCManagerA'"] = 1
	else:
		point["b'OpenSCManagerA'"] = 0

	if "b'OpenSCManagerW'" in xk:
		point["b'OpenSCManagerW'"] = 1
	else:
		point["b'OpenSCManagerW'"] = 0

	if "b'OpenSemaphoreA'" in xk:
		point["b'OpenSemaphoreA'"] = 1
	else:
		point["b'OpenSemaphoreA'"] = 0

	if "b'OpenSemaphoreW'" in xk:
		point["b'OpenSemaphoreW'"] = 1
	else:
		point["b'OpenSemaphoreW'"] = 0

	if "b'OpenServiceA'" in xk:
		point["b'OpenServiceA'"] = 1
	else:
		point["b'OpenServiceA'"] = 0

	if "b'OpenServiceW'" in xk:
		point["b'OpenServiceW'"] = 1
	else:
		point["b'OpenServiceW'"] = 0

	if "b'OpenThemeData'" in xk:
		point["b'OpenThemeData'"] = 1
	else:
		point["b'OpenThemeData'"] = 0

	if "b'OpenThread'" in xk:
		point["b'OpenThread'"] = 1
	else:
		point["b'OpenThread'"] = 0

	if "b'OpenThreadToken'" in xk:
		point["b'OpenThreadToken'"] = 1
	else:
		point["b'OpenThreadToken'"] = 0

	if "b'OpenWindowStationW'" in xk:
		point["b'OpenWindowStationW'"] = 1
	else:
		point["b'OpenWindowStationW'"] = 0

	if "b'OutputDebugStringA'" in xk:
		point["b'OutputDebugStringA'"] = 1
	else:
		point["b'OutputDebugStringA'"] = 0

	if "b'OutputDebugStringW'" in xk:
		point["b'OutputDebugStringW'"] = 1
	else:
		point["b'OutputDebugStringW'"] = 0

	if "b'PackDDElParam'" in xk:
		point["b'PackDDElParam'"] = 1
	else:
		point["b'PackDDElParam'"] = 0

	if "b'PaintDesktop'" in xk:
		point["b'PaintDesktop'"] = 1
	else:
		point["b'PaintDesktop'"] = 0

	if "b'PatBlt'" in xk:
		point["b'PatBlt'"] = 1
	else:
		point["b'PatBlt'"] = 0

	if "b'PathAddBackslashW'" in xk:
		point["b'PathAddBackslashW'"] = 1
	else:
		point["b'PathAddBackslashW'"] = 0

	if "b'PathAppendW'" in xk:
		point["b'PathAppendW'"] = 1
	else:
		point["b'PathAppendW'"] = 0

	if "b'PathCanonicalizeW'" in xk:
		point["b'PathCanonicalizeW'"] = 1
	else:
		point["b'PathCanonicalizeW'"] = 0

	if "b'PathCombineW'" in xk:
		point["b'PathCombineW'"] = 1
	else:
		point["b'PathCombineW'"] = 0

	if "b'PathFileExistsA'" in xk:
		point["b'PathFileExistsA'"] = 1
	else:
		point["b'PathFileExistsA'"] = 0

	if "b'PathFileExistsW'" in xk:
		point["b'PathFileExistsW'"] = 1
	else:
		point["b'PathFileExistsW'"] = 0

	if "b'PathFindExtensionA'" in xk:
		point["b'PathFindExtensionA'"] = 1
	else:
		point["b'PathFindExtensionA'"] = 0

	if "b'PathFindExtensionW'" in xk:
		point["b'PathFindExtensionW'"] = 1
	else:
		point["b'PathFindExtensionW'"] = 0

	if "b'PathFindFileNameA'" in xk:
		point["b'PathFindFileNameA'"] = 1
	else:
		point["b'PathFindFileNameA'"] = 0

	if "b'PathFindFileNameW'" in xk:
		point["b'PathFindFileNameW'"] = 1
	else:
		point["b'PathFindFileNameW'"] = 0

	if "b'PathGetArgsA'" in xk:
		point["b'PathGetArgsA'"] = 1
	else:
		point["b'PathGetArgsA'"] = 0

	if "b'PathGetDriveNumberA'" in xk:
		point["b'PathGetDriveNumberA'"] = 1
	else:
		point["b'PathGetDriveNumberA'"] = 0

	if "b'PathIsDirectoryA'" in xk:
		point["b'PathIsDirectoryA'"] = 1
	else:
		point["b'PathIsDirectoryA'"] = 0

	if "b'PathIsDirectoryW'" in xk:
		point["b'PathIsDirectoryW'"] = 1
	else:
		point["b'PathIsDirectoryW'"] = 0

	if "b'PathIsDirectoryEmptyA'" in xk:
		point["b'PathIsDirectoryEmptyA'"] = 1
	else:
		point["b'PathIsDirectoryEmptyA'"] = 0

	if "b'PathIsRelativeW'" in xk:
		point["b'PathIsRelativeW'"] = 1
	else:
		point["b'PathIsRelativeW'"] = 0

	if "b'PathIsUNCA'" in xk:
		point["b'PathIsUNCA'"] = 1
	else:
		point["b'PathIsUNCA'"] = 0

	if "b'PathIsUNCW'" in xk:
		point["b'PathIsUNCW'"] = 1
	else:
		point["b'PathIsUNCW'"] = 0

	if "b'PathRemoveBlanksA'" in xk:
		point["b'PathRemoveBlanksA'"] = 1
	else:
		point["b'PathRemoveBlanksA'"] = 0

	if "b'PathRemoveExtensionA'" in xk:
		point["b'PathRemoveExtensionA'"] = 1
	else:
		point["b'PathRemoveExtensionA'"] = 0

	if "b'PathRemoveExtensionW'" in xk:
		point["b'PathRemoveExtensionW'"] = 1
	else:
		point["b'PathRemoveExtensionW'"] = 0

	if "b'PathRemoveFileSpecA'" in xk:
		point["b'PathRemoveFileSpecA'"] = 1
	else:
		point["b'PathRemoveFileSpecA'"] = 0

	if "b'PathRemoveFileSpecW'" in xk:
		point["b'PathRemoveFileSpecW'"] = 1
	else:
		point["b'PathRemoveFileSpecW'"] = 0

	if "b'PathStripPathW'" in xk:
		point["b'PathStripPathW'"] = 1
	else:
		point["b'PathStripPathW'"] = 0

	if "b'PathStripToRootA'" in xk:
		point["b'PathStripToRootA'"] = 1
	else:
		point["b'PathStripToRootA'"] = 0

	if "b'PathStripToRootW'" in xk:
		point["b'PathStripToRootW'"] = 1
	else:
		point["b'PathStripToRootW'"] = 0

	if "b'PathToRegion'" in xk:
		point["b'PathToRegion'"] = 1
	else:
		point["b'PathToRegion'"] = 0

	if "b'PeekConsoleInputA'" in xk:
		point["b'PeekConsoleInputA'"] = 1
	else:
		point["b'PeekConsoleInputA'"] = 0

	if "b'PeekMessageA'" in xk:
		point["b'PeekMessageA'"] = 1
	else:
		point["b'PeekMessageA'"] = 0

	if "b'PeekMessageW'" in xk:
		point["b'PeekMessageW'"] = 1
	else:
		point["b'PeekMessageW'"] = 0

	if "b'PeekNamedPipe'" in xk:
		point["b'PeekNamedPipe'"] = 1
	else:
		point["b'PeekNamedPipe'"] = 0

	if "b'PlayEnhMetaFile'" in xk:
		point["b'PlayEnhMetaFile'"] = 1
	else:
		point["b'PlayEnhMetaFile'"] = 0

	if "b'PlayMetaFile'" in xk:
		point["b'PlayMetaFile'"] = 1
	else:
		point["b'PlayMetaFile'"] = 0

	if "b'PlayMetaFileRecord'" in xk:
		point["b'PlayMetaFileRecord'"] = 1
	else:
		point["b'PlayMetaFileRecord'"] = 0

	if "b'PlaySoundA'" in xk:
		point["b'PlaySoundA'"] = 1
	else:
		point["b'PlaySoundA'"] = 0

	if "b'PlaySoundW'" in xk:
		point["b'PlaySoundW'"] = 1
	else:
		point["b'PlaySoundW'"] = 0

	if "b'PolyDraw'" in xk:
		point["b'PolyDraw'"] = 1
	else:
		point["b'PolyDraw'"] = 0

	if "b'GetModuleBaseNameA'" in xk:
		point["b'GetModuleBaseNameA'"] = 1
	else:
		point["b'GetModuleBaseNameA'"] = 0

	if "b'GetModuleBaseNameW'" in xk:
		point["b'GetModuleBaseNameW'"] = 1
	else:
		point["b'GetModuleBaseNameW'"] = 0

	if "b'PolyTextOutA'" in xk:
		point["b'PolyTextOutA'"] = 1
	else:
		point["b'PolyTextOutA'"] = 0

	if "b'Polygon'" in xk:
		point["b'Polygon'"] = 1
	else:
		point["b'Polygon'"] = 0

	if "b'Polyline'" in xk:
		point["b'Polyline'"] = 1
	else:
		point["b'Polyline'"] = 0

	if "b'PolylineTo'" in xk:
		point["b'PolylineTo'"] = 1
	else:
		point["b'PolylineTo'"] = 0

	if "b'PostMessageA'" in xk:
		point["b'PostMessageA'"] = 1
	else:
		point["b'PostMessageA'"] = 0

	if "b'PostMessageW'" in xk:
		point["b'PostMessageW'"] = 1
	else:
		point["b'PostMessageW'"] = 0

	if "b'PostQueuedCompletionStatus'" in xk:
		point["b'PostQueuedCompletionStatus'"] = 1
	else:
		point["b'PostQueuedCompletionStatus'"] = 0

	if "b'PostQuitMessage'" in xk:
		point["b'PostQuitMessage'"] = 1
	else:
		point["b'PostQuitMessage'"] = 0

	if "b'PostThreadMessageA'" in xk:
		point["b'PostThreadMessageA'"] = 1
	else:
		point["b'PostThreadMessageA'"] = 0

	if "b'PostThreadMessageW'" in xk:
		point["b'PostThreadMessageW'"] = 1
	else:
		point["b'PostThreadMessageW'"] = 0

	if "b'PrepareTape'" in xk:
		point["b'PrepareTape'"] = 1
	else:
		point["b'PrepareTape'"] = 0

	if "b'Process32FirstW'" in xk:
		point["b'Process32FirstW'"] = 1
	else:
		point["b'Process32FirstW'"] = 0

	if "b'Process32NextW'" in xk:
		point["b'Process32NextW'"] = 1
	else:
		point["b'Process32NextW'"] = 0

	if "b'ProgIDFromCLSID'" in xk:
		point["b'ProgIDFromCLSID'"] = 1
	else:
		point["b'ProgIDFromCLSID'"] = 0

	if "b'PropertySheetA'" in xk:
		point["b'PropertySheetA'"] = 1
	else:
		point["b'PropertySheetA'"] = 0

	if "b'PropertySheetW'" in xk:
		point["b'PropertySheetW'"] = 1
	else:
		point["b'PropertySheetW'"] = 0

	if "b'PsGetVersion'" in xk:
		point["b'PsGetVersion'"] = 1
	else:
		point["b'PsGetVersion'"] = 0

	if "b'PsLookupProcessByProcessId'" in xk:
		point["b'PsLookupProcessByProcessId'"] = 1
	else:
		point["b'PsLookupProcessByProcessId'"] = 0

	if "b'PtInRect'" in xk:
		point["b'PtInRect'"] = 1
	else:
		point["b'PtInRect'"] = 0

	if "b'PtInRegion'" in xk:
		point["b'PtInRegion'"] = 1
	else:
		point["b'PtInRegion'"] = 0

	if "b'PtVisible'" in xk:
		point["b'PtVisible'"] = 1
	else:
		point["b'PtVisible'"] = 0

	if "b'PulseEvent'" in xk:
		point["b'PulseEvent'"] = 1
	else:
		point["b'PulseEvent'"] = 0

	if "b'QueryDepthSList'" in xk:
		point["b'QueryDepthSList'"] = 1
	else:
		point["b'QueryDepthSList'"] = 0

	if "b'QueryDosDeviceW'" in xk:
		point["b'QueryDosDeviceW'"] = 1
	else:
		point["b'QueryDosDeviceW'"] = 0

	if "b'QueryInformationJobObject'" in xk:
		point["b'QueryInformationJobObject'"] = 1
	else:
		point["b'QueryInformationJobObject'"] = 0

	if "b'QueryPerformanceCounter'" in xk:
		point["b'QueryPerformanceCounter'"] = 1
	else:
		point["b'QueryPerformanceCounter'"] = 0

	if "b'QueryPerformanceFrequency'" in xk:
		point["b'QueryPerformanceFrequency'"] = 1
	else:
		point["b'QueryPerformanceFrequency'"] = 0

	if "b'QueryServiceStatus'" in xk:
		point["b'QueryServiceStatus'"] = 1
	else:
		point["b'QueryServiceStatus'"] = 0

	if "b'QueryServiceStatusEx'" in xk:
		point["b'QueryServiceStatusEx'"] = 1
	else:
		point["b'QueryServiceStatusEx'"] = 0

	if "b'QueueUserAPC'" in xk:
		point["b'QueueUserAPC'"] = 1
	else:
		point["b'QueueUserAPC'"] = 0

	if "b'RaiseException'" in xk:
		point["b'RaiseException'"] = 1
	else:
		point["b'RaiseException'"] = 0

	if "b'RasCreatePhonebookEntryA'" in xk:
		point["b'RasCreatePhonebookEntryA'"] = 1
	else:
		point["b'RasCreatePhonebookEntryA'"] = 0

	if "b'RasDialA'" in xk:
		point["b'RasDialA'"] = 1
	else:
		point["b'RasDialA'"] = 0

	if "b'RasEditPhonebookEntryA'" in xk:
		point["b'RasEditPhonebookEntryA'"] = 1
	else:
		point["b'RasEditPhonebookEntryA'"] = 0

	if "b'RasEnumConnectionsA'" in xk:
		point["b'RasEnumConnectionsA'"] = 1
	else:
		point["b'RasEnumConnectionsA'"] = 0

	if "b'RasEnumEntriesA'" in xk:
		point["b'RasEnumEntriesA'"] = 1
	else:
		point["b'RasEnumEntriesA'"] = 0

	if "b'RasGetConnectStatusA'" in xk:
		point["b'RasGetConnectStatusA'"] = 1
	else:
		point["b'RasGetConnectStatusA'"] = 0

	if "b'RasGetErrorStringA'" in xk:
		point["b'RasGetErrorStringA'"] = 1
	else:
		point["b'RasGetErrorStringA'"] = 0

	if "b'RasGetProjectionInfoA'" in xk:
		point["b'RasGetProjectionInfoA'"] = 1
	else:
		point["b'RasGetProjectionInfoA'"] = 0

	if "b'RasHangUpA'" in xk:
		point["b'RasHangUpA'"] = 1
	else:
		point["b'RasHangUpA'"] = 0

	if "b'ReadConsoleW'" in xk:
		point["b'ReadConsoleW'"] = 1
	else:
		point["b'ReadConsoleW'"] = 0

	if "b'ReadConsoleA'" in xk:
		point["b'ReadConsoleA'"] = 1
	else:
		point["b'ReadConsoleA'"] = 0

	if "b'ReadConsoleInputW'" in xk:
		point["b'ReadConsoleInputW'"] = 1
	else:
		point["b'ReadConsoleInputW'"] = 0

	if "b'ReadConsoleInputExA'" in xk:
		point["b'ReadConsoleInputExA'"] = 1
	else:
		point["b'ReadConsoleInputExA'"] = 0

	if "b'ReadConsoleOutputCharacterA'" in xk:
		point["b'ReadConsoleOutputCharacterA'"] = 1
	else:
		point["b'ReadConsoleOutputCharacterA'"] = 0

	if "b'ReadFile'" in xk:
		point["b'ReadFile'"] = 1
	else:
		point["b'ReadFile'"] = 0

	if "b'ReadProcessMemory'" in xk:
		point["b'ReadProcessMemory'"] = 1
	else:
		point["b'ReadProcessMemory'"] = 0

	if "b'RealChildWindowFromPoint'" in xk:
		point["b'RealChildWindowFromPoint'"] = 1
	else:
		point["b'RealChildWindowFromPoint'"] = 0

	if "b'RealGetWindowClass'" in xk:
		point["b'RealGetWindowClass'"] = 1
	else:
		point["b'RealGetWindowClass'"] = 0

	if "b'RealizePalette'" in xk:
		point["b'RealizePalette'"] = 1
	else:
		point["b'RealizePalette'"] = 0

	if "b'RectVisible'" in xk:
		point["b'RectVisible'"] = 1
	else:
		point["b'RectVisible'"] = 0

	if "b'Rectangle'" in xk:
		point["b'Rectangle'"] = 1
	else:
		point["b'Rectangle'"] = 0

	if "b'RedrawWindow'" in xk:
		point["b'RedrawWindow'"] = 1
	else:
		point["b'RedrawWindow'"] = 0

	if "b'RegCloseKey'" in xk:
		point["b'RegCloseKey'"] = 1
	else:
		point["b'RegCloseKey'"] = 0

	if "b'RegConnectRegistryA'" in xk:
		point["b'RegConnectRegistryA'"] = 1
	else:
		point["b'RegConnectRegistryA'"] = 0

	if "b'RegConnectRegistryW'" in xk:
		point["b'RegConnectRegistryW'"] = 1
	else:
		point["b'RegConnectRegistryW'"] = 0

	if "b'RegCreateKeyA'" in xk:
		point["b'RegCreateKeyA'"] = 1
	else:
		point["b'RegCreateKeyA'"] = 0

	if "b'RegCreateKeyW'" in xk:
		point["b'RegCreateKeyW'"] = 1
	else:
		point["b'RegCreateKeyW'"] = 0

	if "b'RegCreateKeyExA'" in xk:
		point["b'RegCreateKeyExA'"] = 1
	else:
		point["b'RegCreateKeyExA'"] = 0

	if "b'RegCreateKeyExW'" in xk:
		point["b'RegCreateKeyExW'"] = 1
	else:
		point["b'RegCreateKeyExW'"] = 0

	if "b'RegDeleteKeyA'" in xk:
		point["b'RegDeleteKeyA'"] = 1
	else:
		point["b'RegDeleteKeyA'"] = 0

	if "b'RegDeleteKeyW'" in xk:
		point["b'RegDeleteKeyW'"] = 1
	else:
		point["b'RegDeleteKeyW'"] = 0

	if "b'RegDeleteValueA'" in xk:
		point["b'RegDeleteValueA'"] = 1
	else:
		point["b'RegDeleteValueA'"] = 0

	if "b'RegDeleteValueW'" in xk:
		point["b'RegDeleteValueW'"] = 1
	else:
		point["b'RegDeleteValueW'"] = 0

	if "b'RegDisablePredefinedCacheEx'" in xk:
		point["b'RegDisablePredefinedCacheEx'"] = 1
	else:
		point["b'RegDisablePredefinedCacheEx'"] = 0

	if "b'RegEnumKeyA'" in xk:
		point["b'RegEnumKeyA'"] = 1
	else:
		point["b'RegEnumKeyA'"] = 0

	if "b'RegEnumKeyW'" in xk:
		point["b'RegEnumKeyW'"] = 1
	else:
		point["b'RegEnumKeyW'"] = 0

	if "b'RegEnumKeyExA'" in xk:
		point["b'RegEnumKeyExA'"] = 1
	else:
		point["b'RegEnumKeyExA'"] = 0

	if "b'RegEnumKeyExW'" in xk:
		point["b'RegEnumKeyExW'"] = 1
	else:
		point["b'RegEnumKeyExW'"] = 0

	if "b'RegEnumValueA'" in xk:
		point["b'RegEnumValueA'"] = 1
	else:
		point["b'RegEnumValueA'"] = 0

	if "b'RegEnumValueW'" in xk:
		point["b'RegEnumValueW'"] = 1
	else:
		point["b'RegEnumValueW'"] = 0

	if "b'RegFlushKey'" in xk:
		point["b'RegFlushKey'"] = 1
	else:
		point["b'RegFlushKey'"] = 0

	if "b'RegGetKeySecurity'" in xk:
		point["b'RegGetKeySecurity'"] = 1
	else:
		point["b'RegGetKeySecurity'"] = 0

	if "b'RegGetValueA'" in xk:
		point["b'RegGetValueA'"] = 1
	else:
		point["b'RegGetValueA'"] = 0

	if "b'RegLoadKeyA'" in xk:
		point["b'RegLoadKeyA'"] = 1
	else:
		point["b'RegLoadKeyA'"] = 0

	if "b'RegNotifyChangeKeyValue'" in xk:
		point["b'RegNotifyChangeKeyValue'"] = 1
	else:
		point["b'RegNotifyChangeKeyValue'"] = 0

	if "b'RegOpenKeyA'" in xk:
		point["b'RegOpenKeyA'"] = 1
	else:
		point["b'RegOpenKeyA'"] = 0

	if "b'RegOpenKeyW'" in xk:
		point["b'RegOpenKeyW'"] = 1
	else:
		point["b'RegOpenKeyW'"] = 0

	if "b'RegOpenKeyExA'" in xk:
		point["b'RegOpenKeyExA'"] = 1
	else:
		point["b'RegOpenKeyExA'"] = 0

	if "b'RegOpenKeyExW'" in xk:
		point["b'RegOpenKeyExW'"] = 1
	else:
		point["b'RegOpenKeyExW'"] = 0

	if "b'RegQueryInfoKeyA'" in xk:
		point["b'RegQueryInfoKeyA'"] = 1
	else:
		point["b'RegQueryInfoKeyA'"] = 0

	if "b'RegQueryInfoKeyW'" in xk:
		point["b'RegQueryInfoKeyW'"] = 1
	else:
		point["b'RegQueryInfoKeyW'"] = 0

	if "b'RegQueryValueA'" in xk:
		point["b'RegQueryValueA'"] = 1
	else:
		point["b'RegQueryValueA'"] = 0

	if "b'RegQueryValueW'" in xk:
		point["b'RegQueryValueW'"] = 1
	else:
		point["b'RegQueryValueW'"] = 0

	if "b'RegQueryValueExA'" in xk:
		point["b'RegQueryValueExA'"] = 1
	else:
		point["b'RegQueryValueExA'"] = 0

	if "b'RegQueryValueExW'" in xk:
		point["b'RegQueryValueExW'"] = 1
	else:
		point["b'RegQueryValueExW'"] = 0

	if "b'RegReplaceKeyW'" in xk:
		point["b'RegReplaceKeyW'"] = 1
	else:
		point["b'RegReplaceKeyW'"] = 0

	if "b'RegRestoreKeyW'" in xk:
		point["b'RegRestoreKeyW'"] = 1
	else:
		point["b'RegRestoreKeyW'"] = 0

	if "b'RegSetValueA'" in xk:
		point["b'RegSetValueA'"] = 1
	else:
		point["b'RegSetValueA'"] = 0

	if "b'RegSetValueW'" in xk:
		point["b'RegSetValueW'"] = 1
	else:
		point["b'RegSetValueW'"] = 0

	if "b'RegSetValueExA'" in xk:
		point["b'RegSetValueExA'"] = 1
	else:
		point["b'RegSetValueExA'"] = 0

	if "b'RegSetValueExW'" in xk:
		point["b'RegSetValueExW'"] = 1
	else:
		point["b'RegSetValueExW'"] = 0

	if "b'RegUnLoadKeyA'" in xk:
		point["b'RegUnLoadKeyA'"] = 1
	else:
		point["b'RegUnLoadKeyA'"] = 0

	if "b'RegisterClassA'" in xk:
		point["b'RegisterClassA'"] = 1
	else:
		point["b'RegisterClassA'"] = 0

	if "b'RegisterClassW'" in xk:
		point["b'RegisterClassW'"] = 1
	else:
		point["b'RegisterClassW'"] = 0

	if "b'RegisterClassExA'" in xk:
		point["b'RegisterClassExA'"] = 1
	else:
		point["b'RegisterClassExA'"] = 0

	if "b'RegisterClassExW'" in xk:
		point["b'RegisterClassExW'"] = 1
	else:
		point["b'RegisterClassExW'"] = 0

	if "b'RegisterClipboardFormatA'" in xk:
		point["b'RegisterClipboardFormatA'"] = 1
	else:
		point["b'RegisterClipboardFormatA'"] = 0

	if "b'RegisterClipboardFormatW'" in xk:
		point["b'RegisterClipboardFormatW'"] = 1
	else:
		point["b'RegisterClipboardFormatW'"] = 0

	if "b'RegisterConsoleIME'" in xk:
		point["b'RegisterConsoleIME'"] = 1
	else:
		point["b'RegisterConsoleIME'"] = 0

	if "b'RegisterConsoleVDM'" in xk:
		point["b'RegisterConsoleVDM'"] = 1
	else:
		point["b'RegisterConsoleVDM'"] = 0

	if "b'RegisterDeviceNotificationW'" in xk:
		point["b'RegisterDeviceNotificationW'"] = 1
	else:
		point["b'RegisterDeviceNotificationW'"] = 0

	if "b'RegisterDragDrop'" in xk:
		point["b'RegisterDragDrop'"] = 1
	else:
		point["b'RegisterDragDrop'"] = 0

	if "b'RegisterEventSourceA'" in xk:
		point["b'RegisterEventSourceA'"] = 1
	else:
		point["b'RegisterEventSourceA'"] = 0

	if "b'RegisterEventSourceW'" in xk:
		point["b'RegisterEventSourceW'"] = 1
	else:
		point["b'RegisterEventSourceW'"] = 0

	if "b'RegisterHotKey'" in xk:
		point["b'RegisterHotKey'"] = 1
	else:
		point["b'RegisterHotKey'"] = 0

	if "b'RegisterServiceCtrlHandlerA'" in xk:
		point["b'RegisterServiceCtrlHandlerA'"] = 1
	else:
		point["b'RegisterServiceCtrlHandlerA'"] = 0

	if "b'RegisterServiceCtrlHandlerW'" in xk:
		point["b'RegisterServiceCtrlHandlerW'"] = 1
	else:
		point["b'RegisterServiceCtrlHandlerW'"] = 0

	if "b'RegisterServiceCtrlHandlerExW'" in xk:
		point["b'RegisterServiceCtrlHandlerExW'"] = 1
	else:
		point["b'RegisterServiceCtrlHandlerExW'"] = 0

	if "b'RegisterTraceGuidsW'" in xk:
		point["b'RegisterTraceGuidsW'"] = 1
	else:
		point["b'RegisterTraceGuidsW'"] = 0

	if "b'RegisterWaitForSingleObject'" in xk:
		point["b'RegisterWaitForSingleObject'"] = 1
	else:
		point["b'RegisterWaitForSingleObject'"] = 0

	if "b'RegisterWaitForSingleObjectEx'" in xk:
		point["b'RegisterWaitForSingleObjectEx'"] = 1
	else:
		point["b'RegisterWaitForSingleObjectEx'"] = 0

	if "b'RegisterWindowMessageA'" in xk:
		point["b'RegisterWindowMessageA'"] = 1
	else:
		point["b'RegisterWindowMessageA'"] = 0

	if "b'RegisterWindowMessageW'" in xk:
		point["b'RegisterWindowMessageW'"] = 1
	else:
		point["b'RegisterWindowMessageW'"] = 0

	if "b'ReleaseActCtx'" in xk:
		point["b'ReleaseActCtx'"] = 1
	else:
		point["b'ReleaseActCtx'"] = 0

	if "b'ReleaseCapture'" in xk:
		point["b'ReleaseCapture'"] = 1
	else:
		point["b'ReleaseCapture'"] = 0

	if "b'ReleaseDC'" in xk:
		point["b'ReleaseDC'"] = 1
	else:
		point["b'ReleaseDC'"] = 0

	if "b'ReleaseMutex'" in xk:
		point["b'ReleaseMutex'"] = 1
	else:
		point["b'ReleaseMutex'"] = 0

	if "b'ReleaseSemaphore'" in xk:
		point["b'ReleaseSemaphore'"] = 1
	else:
		point["b'ReleaseSemaphore'"] = 0

	if "b'ReleaseStgMedium'" in xk:
		point["b'ReleaseStgMedium'"] = 1
	else:
		point["b'ReleaseStgMedium'"] = 0

	if "b'RemoveDirectoryA'" in xk:
		point["b'RemoveDirectoryA'"] = 1
	else:
		point["b'RemoveDirectoryA'"] = 0

	if "b'RemoveDirectoryW'" in xk:
		point["b'RemoveDirectoryW'"] = 1
	else:
		point["b'RemoveDirectoryW'"] = 0

	if "b'RemoveFontResourceExA'" in xk:
		point["b'RemoveFontResourceExA'"] = 1
	else:
		point["b'RemoveFontResourceExA'"] = 0

	if "b'RemoveMenu'" in xk:
		point["b'RemoveMenu'"] = 1
	else:
		point["b'RemoveMenu'"] = 0

	if "b'RemovePropW'" in xk:
		point["b'RemovePropW'"] = 1
	else:
		point["b'RemovePropW'"] = 0

	if "b'RemovePropA'" in xk:
		point["b'RemovePropA'"] = 1
	else:
		point["b'RemovePropA'"] = 0

	if "b'RemoveVectoredExceptionHandler'" in xk:
		point["b'RemoveVectoredExceptionHandler'"] = 1
	else:
		point["b'RemoveVectoredExceptionHandler'"] = 0

	if "b'ReplaceFileA'" in xk:
		point["b'ReplaceFileA'"] = 1
	else:
		point["b'ReplaceFileA'"] = 0

	if "b'ReplaceFileW'" in xk:
		point["b'ReplaceFileW'"] = 1
	else:
		point["b'ReplaceFileW'"] = 0

	if "b'ReportEventA'" in xk:
		point["b'ReportEventA'"] = 1
	else:
		point["b'ReportEventA'"] = 0

	if "b'ReportEventW'" in xk:
		point["b'ReportEventW'"] = 1
	else:
		point["b'ReportEventW'"] = 0

	if "b'RequestDeviceWakeup'" in xk:
		point["b'RequestDeviceWakeup'"] = 1
	else:
		point["b'RequestDeviceWakeup'"] = 0

	if "b'RequestWakeupLatency'" in xk:
		point["b'RequestWakeupLatency'"] = 1
	else:
		point["b'RequestWakeupLatency'"] = 0

	if "b'ResetEvent'" in xk:
		point["b'ResetEvent'"] = 1
	else:
		point["b'ResetEvent'"] = 0

	if "b'RestoreClusterDatabase'" in xk:
		point["b'RestoreClusterDatabase'"] = 1
	else:
		point["b'RestoreClusterDatabase'"] = 0

	if "b'RestoreDC'" in xk:
		point["b'RestoreDC'"] = 1
	else:
		point["b'RestoreDC'"] = 0

	if "b'ResumeThread'" in xk:
		point["b'ResumeThread'"] = 1
	else:
		point["b'ResumeThread'"] = 0

	if "b'ReuseDDElParam'" in xk:
		point["b'ReuseDDElParam'"] = 1
	else:
		point["b'ReuseDDElParam'"] = 0

	if "b'RevertToSelf'" in xk:
		point["b'RevertToSelf'"] = 1
	else:
		point["b'RevertToSelf'"] = 0

	if "b'RevokeDragDrop'" in xk:
		point["b'RevokeDragDrop'"] = 1
	else:
		point["b'RevokeDragDrop'"] = 0

	if "b'RoundRect'" in xk:
		point["b'RoundRect'"] = 1
	else:
		point["b'RoundRect'"] = 0

	if "b'RtlAddAccessDeniedAce'" in xk:
		point["b'RtlAddAccessDeniedAce'"] = 1
	else:
		point["b'RtlAddAccessDeniedAce'"] = 0

	if "b'RtlAnsiStringToUnicodeString'" in xk:
		point["b'RtlAnsiStringToUnicodeString'"] = 1
	else:
		point["b'RtlAnsiStringToUnicodeString'"] = 0

	if "b'RtlCaptureContext'" in xk:
		point["b'RtlCaptureContext'"] = 1
	else:
		point["b'RtlCaptureContext'"] = 0

	if "b'RtlDeleteElementGenericTable'" in xk:
		point["b'RtlDeleteElementGenericTable'"] = 1
	else:
		point["b'RtlDeleteElementGenericTable'"] = 0

	if "b'RtlFillMemory'" in xk:
		point["b'RtlFillMemory'"] = 1
	else:
		point["b'RtlFillMemory'"] = 0

	if "b'RtlFreeThreadActivationContextStack'" in xk:
		point["b'RtlFreeThreadActivationContextStack'"] = 1
	else:
		point["b'RtlFreeThreadActivationContextStack'"] = 0

	if "b'RtlFreeUnicodeString'" in xk:
		point["b'RtlFreeUnicodeString'"] = 1
	else:
		point["b'RtlFreeUnicodeString'"] = 0

	if "b'RtlGetCurrentPeb'" in xk:
		point["b'RtlGetCurrentPeb'"] = 1
	else:
		point["b'RtlGetCurrentPeb'"] = 0

	if "b'RtlGetNtVersionNumbers'" in xk:
		point["b'RtlGetNtVersionNumbers'"] = 1
	else:
		point["b'RtlGetNtVersionNumbers'"] = 0

	if "b'RtlInitAnsiString'" in xk:
		point["b'RtlInitAnsiString'"] = 1
	else:
		point["b'RtlInitAnsiString'"] = 0

	if "b'RtlInitUnicodeString'" in xk:
		point["b'RtlInitUnicodeString'"] = 1
	else:
		point["b'RtlInitUnicodeString'"] = 0

	if "b'RtlInitializeGenericTable'" in xk:
		point["b'RtlInitializeGenericTable'"] = 1
	else:
		point["b'RtlInitializeGenericTable'"] = 0

	if "b'RtlInitializeSListHead'" in xk:
		point["b'RtlInitializeSListHead'"] = 1
	else:
		point["b'RtlInitializeSListHead'"] = 0

	if "b'RtlInsertElementGenericTable'" in xk:
		point["b'RtlInsertElementGenericTable'"] = 1
	else:
		point["b'RtlInsertElementGenericTable'"] = 0

	if "b'RtlLookupElementGenericTable'" in xk:
		point["b'RtlLookupElementGenericTable'"] = 1
	else:
		point["b'RtlLookupElementGenericTable'"] = 0

	if "b'RtlMoveMemory'" in xk:
		point["b'RtlMoveMemory'"] = 1
	else:
		point["b'RtlMoveMemory'"] = 0

	if "b'RtlNtStatusToDosError'" in xk:
		point["b'RtlNtStatusToDosError'"] = 1
	else:
		point["b'RtlNtStatusToDosError'"] = 0

	if "b'RtlSetAttributesSecurityDescriptor'" in xk:
		point["b'RtlSetAttributesSecurityDescriptor'"] = 1
	else:
		point["b'RtlSetAttributesSecurityDescriptor'"] = 0

	if "b'RtlTimeToTimeFields'" in xk:
		point["b'RtlTimeToTimeFields'"] = 1
	else:
		point["b'RtlTimeToTimeFields'"] = 0

	if "b'RtlUnwind'" in xk:
		point["b'RtlUnwind'"] = 1
	else:
		point["b'RtlUnwind'"] = 0

	if "b'RtlUpcaseUnicodeChar'" in xk:
		point["b'RtlUpcaseUnicodeChar'"] = 1
	else:
		point["b'RtlUpcaseUnicodeChar'"] = 0

	if "b'RtlZeroMemory'" in xk:
		point["b'RtlZeroMemory'"] = 1
	else:
		point["b'RtlZeroMemory'"] = 0

	if "b'RtlxAnsiStringToUnicodeSize'" in xk:
		point["b'RtlxAnsiStringToUnicodeSize'"] = 1
	else:
		point["b'RtlxAnsiStringToUnicodeSize'"] = 0

	if "b'SHAddToRecentDocs'" in xk:
		point["b'SHAddToRecentDocs'"] = 1
	else:
		point["b'SHAddToRecentDocs'"] = 0

	if "b'SHAppBarMessage'" in xk:
		point["b'SHAppBarMessage'"] = 1
	else:
		point["b'SHAppBarMessage'"] = 0

	if "b'SHAutoComplete'" in xk:
		point["b'SHAutoComplete'"] = 1
	else:
		point["b'SHAutoComplete'"] = 0

	if "b'SHBindToParent'" in xk:
		point["b'SHBindToParent'"] = 1
	else:
		point["b'SHBindToParent'"] = 0

	if "b'SHBrowseForFolderA'" in xk:
		point["b'SHBrowseForFolderA'"] = 1
	else:
		point["b'SHBrowseForFolderA'"] = 0

	if "b'SHBrowseForFolderW'" in xk:
		point["b'SHBrowseForFolderW'"] = 1
	else:
		point["b'SHBrowseForFolderW'"] = 0

	if "b'SHChangeNotify'" in xk:
		point["b'SHChangeNotify'"] = 1
	else:
		point["b'SHChangeNotify'"] = 0

	if "b'SHCreateDirectoryExA'" in xk:
		point["b'SHCreateDirectoryExA'"] = 1
	else:
		point["b'SHCreateDirectoryExA'"] = 0

	if "b'SHCreateProcessAsUserW'" in xk:
		point["b'SHCreateProcessAsUserW'"] = 1
	else:
		point["b'SHCreateProcessAsUserW'"] = 0

	if "b'SHCreateShellItem'" in xk:
		point["b'SHCreateShellItem'"] = 1
	else:
		point["b'SHCreateShellItem'"] = 0

	if "b'SHDeleteKeyA'" in xk:
		point["b'SHDeleteKeyA'"] = 1
	else:
		point["b'SHDeleteKeyA'"] = 0

	if "b'SHDeleteKeyW'" in xk:
		point["b'SHDeleteKeyW'"] = 1
	else:
		point["b'SHDeleteKeyW'"] = 0

	if "b'SHDeleteValueW'" in xk:
		point["b'SHDeleteValueW'"] = 1
	else:
		point["b'SHDeleteValueW'"] = 0

	if "b'SHEmptyRecycleBinA'" in xk:
		point["b'SHEmptyRecycleBinA'"] = 1
	else:
		point["b'SHEmptyRecycleBinA'"] = 0

	if "b'SHEmptyRecycleBinW'" in xk:
		point["b'SHEmptyRecycleBinW'"] = 1
	else:
		point["b'SHEmptyRecycleBinW'"] = 0

	if "b'SHFileOperationA'" in xk:
		point["b'SHFileOperationA'"] = 1
	else:
		point["b'SHFileOperationA'"] = 0

	if "b'SHFileOperationW'" in xk:
		point["b'SHFileOperationW'"] = 1
	else:
		point["b'SHFileOperationW'"] = 0

	if "b'SHFree'" in xk:
		point["b'SHFree'"] = 1
	else:
		point["b'SHFree'"] = 0

	if "b'SHGetDataFromIDListA'" in xk:
		point["b'SHGetDataFromIDListA'"] = 1
	else:
		point["b'SHGetDataFromIDListA'"] = 0

	if "b'SHGetDesktopFolder'" in xk:
		point["b'SHGetDesktopFolder'"] = 1
	else:
		point["b'SHGetDesktopFolder'"] = 0

	if "b'SHGetDiskFreeSpaceA'" in xk:
		point["b'SHGetDiskFreeSpaceA'"] = 1
	else:
		point["b'SHGetDiskFreeSpaceA'"] = 0

	if "b'SHGetDiskFreeSpaceExW'" in xk:
		point["b'SHGetDiskFreeSpaceExW'"] = 1
	else:
		point["b'SHGetDiskFreeSpaceExW'"] = 0

	if "b'SHGetFileInfoA'" in xk:
		point["b'SHGetFileInfoA'"] = 1
	else:
		point["b'SHGetFileInfoA'"] = 0

	if "b'SHGetFileInfoW'" in xk:
		point["b'SHGetFileInfoW'"] = 1
	else:
		point["b'SHGetFileInfoW'"] = 0

	if "b'SHGetFolderLocation'" in xk:
		point["b'SHGetFolderLocation'"] = 1
	else:
		point["b'SHGetFolderLocation'"] = 0

	if "b'SHGetFolderPathA'" in xk:
		point["b'SHGetFolderPathA'"] = 1
	else:
		point["b'SHGetFolderPathA'"] = 0

	if "b'SHGetFolderPathW'" in xk:
		point["b'SHGetFolderPathW'"] = 1
	else:
		point["b'SHGetFolderPathW'"] = 0

	if "b'SHGetMalloc'" in xk:
		point["b'SHGetMalloc'"] = 1
	else:
		point["b'SHGetMalloc'"] = 0

	if "b'SHGetPathFromIDListA'" in xk:
		point["b'SHGetPathFromIDListA'"] = 1
	else:
		point["b'SHGetPathFromIDListA'"] = 0

	if "b'SHGetPathFromIDListW'" in xk:
		point["b'SHGetPathFromIDListW'"] = 1
	else:
		point["b'SHGetPathFromIDListW'"] = 0

	if "b'SHGetSettings'" in xk:
		point["b'SHGetSettings'"] = 1
	else:
		point["b'SHGetSettings'"] = 0

	if "b'SHGetSpecialFolderLocation'" in xk:
		point["b'SHGetSpecialFolderLocation'"] = 1
	else:
		point["b'SHGetSpecialFolderLocation'"] = 0

	if "b'SHGetSpecialFolderPathA'" in xk:
		point["b'SHGetSpecialFolderPathA'"] = 1
	else:
		point["b'SHGetSpecialFolderPathA'"] = 0

	if "b'SHGetSpecialFolderPathW'" in xk:
		point["b'SHGetSpecialFolderPathW'"] = 1
	else:
		point["b'SHGetSpecialFolderPathW'"] = 0

	if "b'SHGetValueA'" in xk:
		point["b'SHGetValueA'"] = 1
	else:
		point["b'SHGetValueA'"] = 0

	if "b'SHInvokePrinterCommandW'" in xk:
		point["b'SHInvokePrinterCommandW'"] = 1
	else:
		point["b'SHInvokePrinterCommandW'"] = 0

	if "b'SHIsFileAvailableOffline'" in xk:
		point["b'SHIsFileAvailableOffline'"] = 1
	else:
		point["b'SHIsFileAvailableOffline'"] = 0

	if "b'SHLoadNonloadedIconOverlayIdentifiers'" in xk:
		point["b'SHLoadNonloadedIconOverlayIdentifiers'"] = 1
	else:
		point["b'SHLoadNonloadedIconOverlayIdentifiers'"] = 0

	if "b'SHParseDisplayName'" in xk:
		point["b'SHParseDisplayName'"] = 1
	else:
		point["b'SHParseDisplayName'"] = 0

	if "b'SHPathPrepareForWriteA'" in xk:
		point["b'SHPathPrepareForWriteA'"] = 1
	else:
		point["b'SHPathPrepareForWriteA'"] = 0

	if "b'SHPathPrepareForWriteW'" in xk:
		point["b'SHPathPrepareForWriteW'"] = 1
	else:
		point["b'SHPathPrepareForWriteW'"] = 0

	if "b'SHQueryRecycleBinW'" in xk:
		point["b'SHQueryRecycleBinW'"] = 1
	else:
		point["b'SHQueryRecycleBinW'"] = 0

	if "b'SHQueryValueExW'" in xk:
		point["b'SHQueryValueExW'"] = 1
	else:
		point["b'SHQueryValueExW'"] = 0

	if "b'SHRegWriteUSValueW'" in xk:
		point["b'SHRegWriteUSValueW'"] = 1
	else:
		point["b'SHRegWriteUSValueW'"] = 0

	if "b'STROBJ_bEnum'" in xk:
		point["b'STROBJ_bEnum'"] = 1
	else:
		point["b'STROBJ_bEnum'"] = 0

	if "b'SafeArrayCreate'" in xk:
		point["b'SafeArrayCreate'"] = 1
	else:
		point["b'SafeArrayCreate'"] = 0

	if "b'SafeArrayGetLBound'" in xk:
		point["b'SafeArrayGetLBound'"] = 1
	else:
		point["b'SafeArrayGetLBound'"] = 0

	if "b'SafeArrayGetUBound'" in xk:
		point["b'SafeArrayGetUBound'"] = 1
	else:
		point["b'SafeArrayGetUBound'"] = 0

	if "b'SafeArrayPtrOfIndex'" in xk:
		point["b'SafeArrayPtrOfIndex'"] = 1
	else:
		point["b'SafeArrayPtrOfIndex'"] = 0

	if "b'SaferCloseLevel'" in xk:
		point["b'SaferCloseLevel'"] = 1
	else:
		point["b'SaferCloseLevel'"] = 0

	if "b'SaferComputeTokenFromLevel'" in xk:
		point["b'SaferComputeTokenFromLevel'"] = 1
	else:
		point["b'SaferComputeTokenFromLevel'"] = 0

	if "b'SaferIdentifyLevel'" in xk:
		point["b'SaferIdentifyLevel'"] = 1
	else:
		point["b'SaferIdentifyLevel'"] = 0

	if "b'SaferRecordEventLogEntry'" in xk:
		point["b'SaferRecordEventLogEntry'"] = 1
	else:
		point["b'SaferRecordEventLogEntry'"] = 0

	if "b'SaveDC'" in xk:
		point["b'SaveDC'"] = 1
	else:
		point["b'SaveDC'"] = 0

	if "b'ScaleViewportExtEx'" in xk:
		point["b'ScaleViewportExtEx'"] = 1
	else:
		point["b'ScaleViewportExtEx'"] = 0

	if "b'ScaleWindowExtEx'" in xk:
		point["b'ScaleWindowExtEx'"] = 1
	else:
		point["b'ScaleWindowExtEx'"] = 0

	if "b'ScreenToClient'" in xk:
		point["b'ScreenToClient'"] = 1
	else:
		point["b'ScreenToClient'"] = 0

	if "b'ScrollConsoleScreenBufferW'" in xk:
		point["b'ScrollConsoleScreenBufferW'"] = 1
	else:
		point["b'ScrollConsoleScreenBufferW'"] = 0

	if "b'ScrollWindow'" in xk:
		point["b'ScrollWindow'"] = 1
	else:
		point["b'ScrollWindow'"] = 0

	if "b'SearchPathA'" in xk:
		point["b'SearchPathA'"] = 1
	else:
		point["b'SearchPathA'"] = 0

	if "b'SearchPathW'" in xk:
		point["b'SearchPathW'"] = 1
	else:
		point["b'SearchPathW'"] = 0

	if "b'SelectClipRgn'" in xk:
		point["b'SelectClipRgn'"] = 1
	else:
		point["b'SelectClipRgn'"] = 0

	if "b'SelectObject'" in xk:
		point["b'SelectObject'"] = 1
	else:
		point["b'SelectObject'"] = 0

	if "b'SelectPalette'" in xk:
		point["b'SelectPalette'"] = 1
	else:
		point["b'SelectPalette'"] = 0

	if "b'SendDlgItemMessageA'" in xk:
		point["b'SendDlgItemMessageA'"] = 1
	else:
		point["b'SendDlgItemMessageA'"] = 0

	if "b'SendDlgItemMessageW'" in xk:
		point["b'SendDlgItemMessageW'"] = 1
	else:
		point["b'SendDlgItemMessageW'"] = 0

	if "b'SendIMEMessageExW'" in xk:
		point["b'SendIMEMessageExW'"] = 1
	else:
		point["b'SendIMEMessageExW'"] = 0

	if "b'SendInput'" in xk:
		point["b'SendInput'"] = 1
	else:
		point["b'SendInput'"] = 0

	if "b'SendMessageA'" in xk:
		point["b'SendMessageA'"] = 1
	else:
		point["b'SendMessageA'"] = 0

	if "b'SendMessageW'" in xk:
		point["b'SendMessageW'"] = 1
	else:
		point["b'SendMessageW'"] = 0

	if "b'SendMessageCallbackA'" in xk:
		point["b'SendMessageCallbackA'"] = 1
	else:
		point["b'SendMessageCallbackA'"] = 0

	if "b'SendMessageTimeoutA'" in xk:
		point["b'SendMessageTimeoutA'"] = 1
	else:
		point["b'SendMessageTimeoutA'"] = 0

	if "b'SendMessageTimeoutW'" in xk:
		point["b'SendMessageTimeoutW'"] = 1
	else:
		point["b'SendMessageTimeoutW'"] = 0

	if "b'SendNotifyMessageA'" in xk:
		point["b'SendNotifyMessageA'"] = 1
	else:
		point["b'SendNotifyMessageA'"] = 0

	if "b'SetActiveWindow'" in xk:
		point["b'SetActiveWindow'"] = 1
	else:
		point["b'SetActiveWindow'"] = 0

	if "b'SetBitmapBits'" in xk:
		point["b'SetBitmapBits'"] = 1
	else:
		point["b'SetBitmapBits'"] = 0

	if "b'SetBkColor'" in xk:
		point["b'SetBkColor'"] = 1
	else:
		point["b'SetBkColor'"] = 0

	if "b'SetBkMode'" in xk:
		point["b'SetBkMode'"] = 1
	else:
		point["b'SetBkMode'"] = 0

	if "b'SetBrushOrgEx'" in xk:
		point["b'SetBrushOrgEx'"] = 1
	else:
		point["b'SetBrushOrgEx'"] = 0

	if "b'SetCalendarInfoA'" in xk:
		point["b'SetCalendarInfoA'"] = 1
	else:
		point["b'SetCalendarInfoA'"] = 0

	if "b'SetCapture'" in xk:
		point["b'SetCapture'"] = 1
	else:
		point["b'SetCapture'"] = 0

	if "b'SetCaretBlinkTime'" in xk:
		point["b'SetCaretBlinkTime'"] = 1
	else:
		point["b'SetCaretBlinkTime'"] = 0

	if "b'SetCaretPos'" in xk:
		point["b'SetCaretPos'"] = 1
	else:
		point["b'SetCaretPos'"] = 0

	if "b'SetClassLongA'" in xk:
		point["b'SetClassLongA'"] = 1
	else:
		point["b'SetClassLongA'"] = 0

	if "b'SetClassLongW'" in xk:
		point["b'SetClassLongW'"] = 1
	else:
		point["b'SetClassLongW'"] = 0

	if "b'SetClipboardData'" in xk:
		point["b'SetClipboardData'"] = 1
	else:
		point["b'SetClipboardData'"] = 0

	if "b'SetClipboardViewer'" in xk:
		point["b'SetClipboardViewer'"] = 1
	else:
		point["b'SetClipboardViewer'"] = 0

	if "b'SetComputerNameA'" in xk:
		point["b'SetComputerNameA'"] = 1
	else:
		point["b'SetComputerNameA'"] = 0

	if "b'SetConsoleCtrlHandler'" in xk:
		point["b'SetConsoleCtrlHandler'"] = 1
	else:
		point["b'SetConsoleCtrlHandler'"] = 0

	if "b'SetConsoleCursorInfo'" in xk:
		point["b'SetConsoleCursorInfo'"] = 1
	else:
		point["b'SetConsoleCursorInfo'"] = 0

	if "b'SetConsoleCursorPosition'" in xk:
		point["b'SetConsoleCursorPosition'"] = 1
	else:
		point["b'SetConsoleCursorPosition'"] = 0

	if "b'SetConsoleFont'" in xk:
		point["b'SetConsoleFont'"] = 1
	else:
		point["b'SetConsoleFont'"] = 0

	if "b'SetConsoleInputExeNameA'" in xk:
		point["b'SetConsoleInputExeNameA'"] = 1
	else:
		point["b'SetConsoleInputExeNameA'"] = 0

	if "b'SetConsoleMode'" in xk:
		point["b'SetConsoleMode'"] = 1
	else:
		point["b'SetConsoleMode'"] = 0

	if "b'SetConsoleNumberOfCommandsW'" in xk:
		point["b'SetConsoleNumberOfCommandsW'"] = 1
	else:
		point["b'SetConsoleNumberOfCommandsW'"] = 0

	if "b'SetConsoleOutputCP'" in xk:
		point["b'SetConsoleOutputCP'"] = 1
	else:
		point["b'SetConsoleOutputCP'"] = 0

	if "b'SetConsoleScreenBufferSize'" in xk:
		point["b'SetConsoleScreenBufferSize'"] = 1
	else:
		point["b'SetConsoleScreenBufferSize'"] = 0

	if "b'SetConsoleTextAttribute'" in xk:
		point["b'SetConsoleTextAttribute'"] = 1
	else:
		point["b'SetConsoleTextAttribute'"] = 0

	if "b'SetConsoleTitleW'" in xk:
		point["b'SetConsoleTitleW'"] = 1
	else:
		point["b'SetConsoleTitleW'"] = 0

	if "b'SetCriticalSectionSpinCount'" in xk:
		point["b'SetCriticalSectionSpinCount'"] = 1
	else:
		point["b'SetCriticalSectionSpinCount'"] = 0

	if "b'SetCurrentDirectoryA'" in xk:
		point["b'SetCurrentDirectoryA'"] = 1
	else:
		point["b'SetCurrentDirectoryA'"] = 0

	if "b'SetCurrentDirectoryW'" in xk:
		point["b'SetCurrentDirectoryW'"] = 1
	else:
		point["b'SetCurrentDirectoryW'"] = 0

	if "b'SetCursor'" in xk:
		point["b'SetCursor'"] = 1
	else:
		point["b'SetCursor'"] = 0

	if "b'SetCursorPos'" in xk:
		point["b'SetCursorPos'"] = 1
	else:
		point["b'SetCursorPos'"] = 0

	if "b'SetDCBrushColor'" in xk:
		point["b'SetDCBrushColor'"] = 1
	else:
		point["b'SetDCBrushColor'"] = 0

	if "b'SetDIBColorTable'" in xk:
		point["b'SetDIBColorTable'"] = 1
	else:
		point["b'SetDIBColorTable'"] = 0

	if "b'SetDIBits'" in xk:
		point["b'SetDIBits'"] = 1
	else:
		point["b'SetDIBits'"] = 0

	if "b'SetDIBitsToDevice'" in xk:
		point["b'SetDIBitsToDevice'"] = 1
	else:
		point["b'SetDIBitsToDevice'"] = 0

	if "b'SetDefaultCommConfigA'" in xk:
		point["b'SetDefaultCommConfigA'"] = 1
	else:
		point["b'SetDefaultCommConfigA'"] = 0

	if "b'SetDlgItemInt'" in xk:
		point["b'SetDlgItemInt'"] = 1
	else:
		point["b'SetDlgItemInt'"] = 0

	if "b'SetDlgItemTextA'" in xk:
		point["b'SetDlgItemTextA'"] = 1
	else:
		point["b'SetDlgItemTextA'"] = 0

	if "b'SetDlgItemTextW'" in xk:
		point["b'SetDlgItemTextW'"] = 1
	else:
		point["b'SetDlgItemTextW'"] = 0

	if "b'SetDllDirectoryA'" in xk:
		point["b'SetDllDirectoryA'"] = 1
	else:
		point["b'SetDllDirectoryA'"] = 0

	if "b'SetDllDirectoryW'" in xk:
		point["b'SetDllDirectoryW'"] = 1
	else:
		point["b'SetDllDirectoryW'"] = 0

	if "b'SetEndOfFile'" in xk:
		point["b'SetEndOfFile'"] = 1
	else:
		point["b'SetEndOfFile'"] = 0

	if "b'SetEnhMetaFileBits'" in xk:
		point["b'SetEnhMetaFileBits'"] = 1
	else:
		point["b'SetEnhMetaFileBits'"] = 0

	if "b'SetEntriesInAclA'" in xk:
		point["b'SetEntriesInAclA'"] = 1
	else:
		point["b'SetEntriesInAclA'"] = 0

	if "b'SetEntriesInAclW'" in xk:
		point["b'SetEntriesInAclW'"] = 1
	else:
		point["b'SetEntriesInAclW'"] = 0

	if "b'SetEnvironmentVariableA'" in xk:
		point["b'SetEnvironmentVariableA'"] = 1
	else:
		point["b'SetEnvironmentVariableA'"] = 0

	if "b'SetEnvironmentVariableW'" in xk:
		point["b'SetEnvironmentVariableW'"] = 1
	else:
		point["b'SetEnvironmentVariableW'"] = 0

	if "b'SetErrorMode'" in xk:
		point["b'SetErrorMode'"] = 1
	else:
		point["b'SetErrorMode'"] = 0

	if "b'SetEvent'" in xk:
		point["b'SetEvent'"] = 1
	else:
		point["b'SetEvent'"] = 0

	if "b'SetFileApisToANSI'" in xk:
		point["b'SetFileApisToANSI'"] = 1
	else:
		point["b'SetFileApisToANSI'"] = 0

	if "b'SetFileApisToOEM'" in xk:
		point["b'SetFileApisToOEM'"] = 1
	else:
		point["b'SetFileApisToOEM'"] = 0

	if "b'SetFileAttributesA'" in xk:
		point["b'SetFileAttributesA'"] = 1
	else:
		point["b'SetFileAttributesA'"] = 0

	if "b'SetFileAttributesW'" in xk:
		point["b'SetFileAttributesW'"] = 1
	else:
		point["b'SetFileAttributesW'"] = 0

	if "b'SetFilePointer'" in xk:
		point["b'SetFilePointer'"] = 1
	else:
		point["b'SetFilePointer'"] = 0

	if "b'SetFilePointerEx'" in xk:
		point["b'SetFilePointerEx'"] = 1
	else:
		point["b'SetFilePointerEx'"] = 0

	if "b'SetFileSecurityA'" in xk:
		point["b'SetFileSecurityA'"] = 1
	else:
		point["b'SetFileSecurityA'"] = 0

	if "b'SetFileSecurityW'" in xk:
		point["b'SetFileSecurityW'"] = 1
	else:
		point["b'SetFileSecurityW'"] = 0

	if "b'SetFileTime'" in xk:
		point["b'SetFileTime'"] = 1
	else:
		point["b'SetFileTime'"] = 0

	if "b'SetFocus'" in xk:
		point["b'SetFocus'"] = 1
	else:
		point["b'SetFocus'"] = 0

	if "b'SetForegroundWindow'" in xk:
		point["b'SetForegroundWindow'"] = 1
	else:
		point["b'SetForegroundWindow'"] = 0

	if "b'SetHandleCount'" in xk:
		point["b'SetHandleCount'"] = 1
	else:
		point["b'SetHandleCount'"] = 0

	if "b'SetHandleInformation'" in xk:
		point["b'SetHandleInformation'"] = 1
	else:
		point["b'SetHandleInformation'"] = 0

	if "b'SetICMMode'" in xk:
		point["b'SetICMMode'"] = 1
	else:
		point["b'SetICMMode'"] = 0

	if "b'SetKeyboardState'" in xk:
		point["b'SetKeyboardState'"] = 1
	else:
		point["b'SetKeyboardState'"] = 0

	if "b'SetLastError'" in xk:
		point["b'SetLastError'"] = 1
	else:
		point["b'SetLastError'"] = 0

	if "b'SetLayeredWindowAttributes'" in xk:
		point["b'SetLayeredWindowAttributes'"] = 1
	else:
		point["b'SetLayeredWindowAttributes'"] = 0

	if "b'SetLayout'" in xk:
		point["b'SetLayout'"] = 1
	else:
		point["b'SetLayout'"] = 0

	if "b'SetLocalTime'" in xk:
		point["b'SetLocalTime'"] = 1
	else:
		point["b'SetLocalTime'"] = 0

	if "b'SetLocaleInfoA'" in xk:
		point["b'SetLocaleInfoA'"] = 1
	else:
		point["b'SetLocaleInfoA'"] = 0

	if "b'SetMailslotInfo'" in xk:
		point["b'SetMailslotInfo'"] = 1
	else:
		point["b'SetMailslotInfo'"] = 0

	if "b'SetMapMode'" in xk:
		point["b'SetMapMode'"] = 1
	else:
		point["b'SetMapMode'"] = 0

	if "b'SetMapperFlags'" in xk:
		point["b'SetMapperFlags'"] = 1
	else:
		point["b'SetMapperFlags'"] = 0

	if "b'SetMenu'" in xk:
		point["b'SetMenu'"] = 1
	else:
		point["b'SetMenu'"] = 0

	if "b'SetMenuDefaultItem'" in xk:
		point["b'SetMenuDefaultItem'"] = 1
	else:
		point["b'SetMenuDefaultItem'"] = 0

	if "b'SetMenuInfo'" in xk:
		point["b'SetMenuInfo'"] = 1
	else:
		point["b'SetMenuInfo'"] = 0

	if "b'SetMenuItemBitmaps'" in xk:
		point["b'SetMenuItemBitmaps'"] = 1
	else:
		point["b'SetMenuItemBitmaps'"] = 0

	if "b'SetMenuItemInfoA'" in xk:
		point["b'SetMenuItemInfoA'"] = 1
	else:
		point["b'SetMenuItemInfoA'"] = 0

	if "b'SetMenuItemInfoW'" in xk:
		point["b'SetMenuItemInfoW'"] = 1
	else:
		point["b'SetMenuItemInfoW'"] = 0

	if "b'SetMessageQueue'" in xk:
		point["b'SetMessageQueue'"] = 1
	else:
		point["b'SetMessageQueue'"] = 0

	if "b'SetMetaRgn'" in xk:
		point["b'SetMetaRgn'"] = 1
	else:
		point["b'SetMetaRgn'"] = 0

	if "b'SetMiterLimit'" in xk:
		point["b'SetMiterLimit'"] = 1
	else:
		point["b'SetMiterLimit'"] = 0

	if "b'SetNamedPipeHandleState'" in xk:
		point["b'SetNamedPipeHandleState'"] = 1
	else:
		point["b'SetNamedPipeHandleState'"] = 0

	if "b'SetNamedSecurityInfoW'" in xk:
		point["b'SetNamedSecurityInfoW'"] = 1
	else:
		point["b'SetNamedSecurityInfoW'"] = 0

	if "b'SetPaletteEntries'" in xk:
		point["b'SetPaletteEntries'"] = 1
	else:
		point["b'SetPaletteEntries'"] = 0

	if "b'SetParent'" in xk:
		point["b'SetParent'"] = 1
	else:
		point["b'SetParent'"] = 0

	if "b'SetPixel'" in xk:
		point["b'SetPixel'"] = 1
	else:
		point["b'SetPixel'"] = 0

	if "b'SetPixelV'" in xk:
		point["b'SetPixelV'"] = 1
	else:
		point["b'SetPixelV'"] = 0

	if "b'SetPolyFillMode'" in xk:
		point["b'SetPolyFillMode'"] = 1
	else:
		point["b'SetPolyFillMode'"] = 0

	if "b'SetPriorityClass'" in xk:
		point["b'SetPriorityClass'"] = 1
	else:
		point["b'SetPriorityClass'"] = 0

	if "b'SetProcessAffinityMask'" in xk:
		point["b'SetProcessAffinityMask'"] = 1
	else:
		point["b'SetProcessAffinityMask'"] = 0

	if "b'SetProcessPriorityBoost'" in xk:
		point["b'SetProcessPriorityBoost'"] = 1
	else:
		point["b'SetProcessPriorityBoost'"] = 0

	if "b'SetProcessWindowStation'" in xk:
		point["b'SetProcessWindowStation'"] = 1
	else:
		point["b'SetProcessWindowStation'"] = 0

	if "b'SetProcessWorkingSetSize'" in xk:
		point["b'SetProcessWorkingSetSize'"] = 1
	else:
		point["b'SetProcessWorkingSetSize'"] = 0

	if "b'SetPropA'" in xk:
		point["b'SetPropA'"] = 1
	else:
		point["b'SetPropA'"] = 0

	if "b'SetPropW'" in xk:
		point["b'SetPropW'"] = 1
	else:
		point["b'SetPropW'"] = 0

	if "b'SetROP2'" in xk:
		point["b'SetROP2'"] = 1
	else:
		point["b'SetROP2'"] = 0

	if "b'SetRect'" in xk:
		point["b'SetRect'"] = 1
	else:
		point["b'SetRect'"] = 0

	if "b'SetRectEmpty'" in xk:
		point["b'SetRectEmpty'"] = 1
	else:
		point["b'SetRectEmpty'"] = 0

	if "b'SetRectRgn'" in xk:
		point["b'SetRectRgn'"] = 1
	else:
		point["b'SetRectRgn'"] = 0

	if "b'SetScrollInfo'" in xk:
		point["b'SetScrollInfo'"] = 1
	else:
		point["b'SetScrollInfo'"] = 0

	if "b'SetScrollPos'" in xk:
		point["b'SetScrollPos'"] = 1
	else:
		point["b'SetScrollPos'"] = 0

	if "b'SetScrollRange'" in xk:
		point["b'SetScrollRange'"] = 1
	else:
		point["b'SetScrollRange'"] = 0

	if "b'SetSecurityDescriptorDacl'" in xk:
		point["b'SetSecurityDescriptorDacl'"] = 1
	else:
		point["b'SetSecurityDescriptorDacl'"] = 0

	if "b'SetSecurityDescriptorGroup'" in xk:
		point["b'SetSecurityDescriptorGroup'"] = 1
	else:
		point["b'SetSecurityDescriptorGroup'"] = 0

	if "b'SetSecurityDescriptorOwner'" in xk:
		point["b'SetSecurityDescriptorOwner'"] = 1
	else:
		point["b'SetSecurityDescriptorOwner'"] = 0

	if "b'SetSecurityDescriptorSacl'" in xk:
		point["b'SetSecurityDescriptorSacl'"] = 1
	else:
		point["b'SetSecurityDescriptorSacl'"] = 0

	if "b'SetServiceStatus'" in xk:
		point["b'SetServiceStatus'"] = 1
	else:
		point["b'SetServiceStatus'"] = 0

	if "b'SetStdHandle'" in xk:
		point["b'SetStdHandle'"] = 1
	else:
		point["b'SetStdHandle'"] = 0

	if "b'SetStretchBltMode'" in xk:
		point["b'SetStretchBltMode'"] = 1
	else:
		point["b'SetStretchBltMode'"] = 0

	if "b'SetSysColors'" in xk:
		point["b'SetSysColors'"] = 1
	else:
		point["b'SetSysColors'"] = 0

	if "b'SetSystemPowerState'" in xk:
		point["b'SetSystemPowerState'"] = 1
	else:
		point["b'SetSystemPowerState'"] = 0

	if "b'SetSystemTime'" in xk:
		point["b'SetSystemTime'"] = 1
	else:
		point["b'SetSystemTime'"] = 0

	if "b'SetTextAlign'" in xk:
		point["b'SetTextAlign'"] = 1
	else:
		point["b'SetTextAlign'"] = 0

	if "b'SetTextColor'" in xk:
		point["b'SetTextColor'"] = 1
	else:
		point["b'SetTextColor'"] = 0

	if "b'SetThreadAffinityMask'" in xk:
		point["b'SetThreadAffinityMask'"] = 1
	else:
		point["b'SetThreadAffinityMask'"] = 0

	if "b'SetThreadContext'" in xk:
		point["b'SetThreadContext'"] = 1
	else:
		point["b'SetThreadContext'"] = 0

	if "b'SetThreadDesktop'" in xk:
		point["b'SetThreadDesktop'"] = 1
	else:
		point["b'SetThreadDesktop'"] = 0

	if "b'SetThreadExecutionState'" in xk:
		point["b'SetThreadExecutionState'"] = 1
	else:
		point["b'SetThreadExecutionState'"] = 0

	if "b'SetThreadLocale'" in xk:
		point["b'SetThreadLocale'"] = 1
	else:
		point["b'SetThreadLocale'"] = 0

	if "b'SetThreadPriority'" in xk:
		point["b'SetThreadPriority'"] = 1
	else:
		point["b'SetThreadPriority'"] = 0

	if "b'SetThreadToken'" in xk:
		point["b'SetThreadToken'"] = 1
	else:
		point["b'SetThreadToken'"] = 0

	if "b'SetTimer'" in xk:
		point["b'SetTimer'"] = 1
	else:
		point["b'SetTimer'"] = 0

	if "b'SetTokenInformation'" in xk:
		point["b'SetTokenInformation'"] = 1
	else:
		point["b'SetTokenInformation'"] = 0

	if "b'SetUnhandledExceptionFilter'" in xk:
		point["b'SetUnhandledExceptionFilter'"] = 1
	else:
		point["b'SetUnhandledExceptionFilter'"] = 0

	if "b'SetUserObjectInformationW'" in xk:
		point["b'SetUserObjectInformationW'"] = 1
	else:
		point["b'SetUserObjectInformationW'"] = 0

	if "b'SetUserObjectSecurity'" in xk:
		point["b'SetUserObjectSecurity'"] = 1
	else:
		point["b'SetUserObjectSecurity'"] = 0

	if "b'SetViewportExtEx'" in xk:
		point["b'SetViewportExtEx'"] = 1
	else:
		point["b'SetViewportExtEx'"] = 0

	if "b'SetViewportOrgEx'" in xk:
		point["b'SetViewportOrgEx'"] = 1
	else:
		point["b'SetViewportOrgEx'"] = 0

	if "b'SetVolumeLabelA'" in xk:
		point["b'SetVolumeLabelA'"] = 1
	else:
		point["b'SetVolumeLabelA'"] = 0

	if "b'SetVolumeLabelW'" in xk:
		point["b'SetVolumeLabelW'"] = 1
	else:
		point["b'SetVolumeLabelW'"] = 0

	if "b'SetVolumeMountPointW'" in xk:
		point["b'SetVolumeMountPointW'"] = 1
	else:
		point["b'SetVolumeMountPointW'"] = 0

	if "b'SetWaitableTimer'" in xk:
		point["b'SetWaitableTimer'"] = 1
	else:
		point["b'SetWaitableTimer'"] = 0

	if "b'SetWMetaFileBits'" in xk:
		point["b'SetWMetaFileBits'"] = 1
	else:
		point["b'SetWMetaFileBits'"] = 0

	if "b'SetWindowContextHelpId'" in xk:
		point["b'SetWindowContextHelpId'"] = 1
	else:
		point["b'SetWindowContextHelpId'"] = 0

	if "b'SetWindowExtEx'" in xk:
		point["b'SetWindowExtEx'"] = 1
	else:
		point["b'SetWindowExtEx'"] = 0

	if "b'SetWindowLongA'" in xk:
		point["b'SetWindowLongA'"] = 1
	else:
		point["b'SetWindowLongA'"] = 0

	if "b'SetWindowLongW'" in xk:
		point["b'SetWindowLongW'"] = 1
	else:
		point["b'SetWindowLongW'"] = 0

	if "b'SetWindowOrgEx'" in xk:
		point["b'SetWindowOrgEx'"] = 1
	else:
		point["b'SetWindowOrgEx'"] = 0

	if "b'SetWindowPlacement'" in xk:
		point["b'SetWindowPlacement'"] = 1
	else:
		point["b'SetWindowPlacement'"] = 0

	if "b'SetWindowPos'" in xk:
		point["b'SetWindowPos'"] = 1
	else:
		point["b'SetWindowPos'"] = 0

	if "b'SetWindowRgn'" in xk:
		point["b'SetWindowRgn'"] = 1
	else:
		point["b'SetWindowRgn'"] = 0

	if "b'SetWindowTextA'" in xk:
		point["b'SetWindowTextA'"] = 1
	else:
		point["b'SetWindowTextA'"] = 0

	if "b'SetWindowTextW'" in xk:
		point["b'SetWindowTextW'"] = 1
	else:
		point["b'SetWindowTextW'"] = 0

	if "b'SetWindowTheme'" in xk:
		point["b'SetWindowTheme'"] = 1
	else:
		point["b'SetWindowTheme'"] = 0

	if "b'SetWindowsHookExA'" in xk:
		point["b'SetWindowsHookExA'"] = 1
	else:
		point["b'SetWindowsHookExA'"] = 0

	if "b'SetWindowsHookExW'" in xk:
		point["b'SetWindowsHookExW'"] = 1
	else:
		point["b'SetWindowsHookExW'"] = 0

	if "b'SetupComm'" in xk:
		point["b'SetupComm'"] = 1
	else:
		point["b'SetupComm'"] = 0

	if "b'SetupCopyOEMInfW'" in xk:
		point["b'SetupCopyOEMInfW'"] = 1
	else:
		point["b'SetupCopyOEMInfW'"] = 0

	if "b'SetupDiDestroyDeviceInfoList'" in xk:
		point["b'SetupDiDestroyDeviceInfoList'"] = 1
	else:
		point["b'SetupDiDestroyDeviceInfoList'"] = 0

	if "b'SetupDiEnumDeviceInterfaces'" in xk:
		point["b'SetupDiEnumDeviceInterfaces'"] = 1
	else:
		point["b'SetupDiEnumDeviceInterfaces'"] = 0

	if "b'SetupDiGetClassDevsA'" in xk:
		point["b'SetupDiGetClassDevsA'"] = 1
	else:
		point["b'SetupDiGetClassDevsA'"] = 0

	if "b'SetupDiGetDeviceInterfaceDetailA'" in xk:
		point["b'SetupDiGetDeviceInterfaceDetailA'"] = 1
	else:
		point["b'SetupDiGetDeviceInterfaceDetailA'"] = 0

	if "b'ShellAboutA'" in xk:
		point["b'ShellAboutA'"] = 1
	else:
		point["b'ShellAboutA'"] = 0

	if "b'ShellAboutW'" in xk:
		point["b'ShellAboutW'"] = 1
	else:
		point["b'ShellAboutW'"] = 0

	if "b'ShellExecuteA'" in xk:
		point["b'ShellExecuteA'"] = 1
	else:
		point["b'ShellExecuteA'"] = 0

	if "b'ShellExecuteW'" in xk:
		point["b'ShellExecuteW'"] = 1
	else:
		point["b'ShellExecuteW'"] = 0

	if "b'ShellExecuteExA'" in xk:
		point["b'ShellExecuteExA'"] = 1
	else:
		point["b'ShellExecuteExA'"] = 0

	if "b'ShellExecuteExW'" in xk:
		point["b'ShellExecuteExW'"] = 1
	else:
		point["b'ShellExecuteExW'"] = 0

	if "b'Shell_NotifyIconA'" in xk:
		point["b'Shell_NotifyIconA'"] = 1
	else:
		point["b'Shell_NotifyIconA'"] = 0

	if "b'Shell_NotifyIconW'" in xk:
		point["b'Shell_NotifyIconW'"] = 1
	else:
		point["b'Shell_NotifyIconW'"] = 0

	if "b'ShowCaret'" in xk:
		point["b'ShowCaret'"] = 1
	else:
		point["b'ShowCaret'"] = 0

	if "b'ShowCursor'" in xk:
		point["b'ShowCursor'"] = 1
	else:
		point["b'ShowCursor'"] = 0

	if "b'ShowOwnedPopups'" in xk:
		point["b'ShowOwnedPopups'"] = 1
	else:
		point["b'ShowOwnedPopups'"] = 0

	if "b'ShowScrollBar'" in xk:
		point["b'ShowScrollBar'"] = 1
	else:
		point["b'ShowScrollBar'"] = 0

	if "b'ShowWindow'" in xk:
		point["b'ShowWindow'"] = 1
	else:
		point["b'ShowWindow'"] = 0

	if "b'ShowWindowAsync'" in xk:
		point["b'ShowWindowAsync'"] = 1
	else:
		point["b'ShowWindowAsync'"] = 0

	if "b'SignalObjectAndWait'" in xk:
		point["b'SignalObjectAndWait'"] = 1
	else:
		point["b'SignalObjectAndWait'"] = 0

	if "b'SizeofResource'" in xk:
		point["b'SizeofResource'"] = 1
	else:
		point["b'SizeofResource'"] = 0

	if "b'Sleep'" in xk:
		point["b'Sleep'"] = 1
	else:
		point["b'Sleep'"] = 0

	if "b'SleepEx'" in xk:
		point["b'SleepEx'"] = 1
	else:
		point["b'SleepEx'"] = 0

	if "b'StackWalk'" in xk:
		point["b'StackWalk'"] = 1
	else:
		point["b'StackWalk'"] = 0

	if "b'StartDocA'" in xk:
		point["b'StartDocA'"] = 1
	else:
		point["b'StartDocA'"] = 0

	if "b'StartPage'" in xk:
		point["b'StartPage'"] = 1
	else:
		point["b'StartPage'"] = 0

	if "b'StartServiceA'" in xk:
		point["b'StartServiceA'"] = 1
	else:
		point["b'StartServiceA'"] = 0

	if "b'StartServiceW'" in xk:
		point["b'StartServiceW'"] = 1
	else:
		point["b'StartServiceW'"] = 0

	if "b'StartServiceCtrlDispatcherA'" in xk:
		point["b'StartServiceCtrlDispatcherA'"] = 1
	else:
		point["b'StartServiceCtrlDispatcherA'"] = 0

	if "b'StartServiceCtrlDispatcherW'" in xk:
		point["b'StartServiceCtrlDispatcherW'"] = 1
	else:
		point["b'StartServiceCtrlDispatcherW'"] = 0

	if "b'StgCreateDocfile'" in xk:
		point["b'StgCreateDocfile'"] = 1
	else:
		point["b'StgCreateDocfile'"] = 0

	if "b'StgCreateDocfileOnILockBytes'" in xk:
		point["b'StgCreateDocfileOnILockBytes'"] = 1
	else:
		point["b'StgCreateDocfileOnILockBytes'"] = 0

	if "b'StgOpenStorage'" in xk:
		point["b'StgOpenStorage'"] = 1
	else:
		point["b'StgOpenStorage'"] = 0

	if "b'StgOpenStorageOnILockBytes'" in xk:
		point["b'StgOpenStorageOnILockBytes'"] = 1
	else:
		point["b'StgOpenStorageOnILockBytes'"] = 0

	if "b'StrCatW'" in xk:
		point["b'StrCatW'"] = 1
	else:
		point["b'StrCatW'"] = 0

	if "b'StrChrA'" in xk:
		point["b'StrChrA'"] = 1
	else:
		point["b'StrChrA'"] = 0

	if "b'StrChrW'" in xk:
		point["b'StrChrW'"] = 1
	else:
		point["b'StrChrW'"] = 0

	if "b'StrChrIW'" in xk:
		point["b'StrChrIW'"] = 1
	else:
		point["b'StrChrIW'"] = 0

	if "b'StrCmpW'" in xk:
		point["b'StrCmpW'"] = 1
	else:
		point["b'StrCmpW'"] = 0

	if "b'StrCmpIW'" in xk:
		point["b'StrCmpIW'"] = 1
	else:
		point["b'StrCmpIW'"] = 0

	if "b'StrCmpNA'" in xk:
		point["b'StrCmpNA'"] = 1
	else:
		point["b'StrCmpNA'"] = 0

	if "b'StrCmpNW'" in xk:
		point["b'StrCmpNW'"] = 1
	else:
		point["b'StrCmpNW'"] = 0

	if "b'StrCmpNIA'" in xk:
		point["b'StrCmpNIA'"] = 1
	else:
		point["b'StrCmpNIA'"] = 0

	if "b'StrCmpNIW'" in xk:
		point["b'StrCmpNIW'"] = 1
	else:
		point["b'StrCmpNIW'"] = 0

	if "b'StrCpyNW'" in xk:
		point["b'StrCpyNW'"] = 1
	else:
		point["b'StrCpyNW'"] = 0

	if "b'StrFormatKBSizeW'" in xk:
		point["b'StrFormatKBSizeW'"] = 1
	else:
		point["b'StrFormatKBSizeW'"] = 0

	if "b'StrPBrkA'" in xk:
		point["b'StrPBrkA'"] = 1
	else:
		point["b'StrPBrkA'"] = 0

	if "b'StrRChrA'" in xk:
		point["b'StrRChrA'"] = 1
	else:
		point["b'StrRChrA'"] = 0

	if "b'StrRChrW'" in xk:
		point["b'StrRChrW'"] = 1
	else:
		point["b'StrRChrW'"] = 0

	if "b'StrRChrIA'" in xk:
		point["b'StrRChrIA'"] = 1
	else:
		point["b'StrRChrIA'"] = 0

	if "b'StrRStrIW'" in xk:
		point["b'StrRStrIW'"] = 1
	else:
		point["b'StrRStrIW'"] = 0

	if "b'StrStrA'" in xk:
		point["b'StrStrA'"] = 1
	else:
		point["b'StrStrA'"] = 0

	if "b'StrStrW'" in xk:
		point["b'StrStrW'"] = 1
	else:
		point["b'StrStrW'"] = 0

	if "b'StrStrIA'" in xk:
		point["b'StrStrIA'"] = 1
	else:
		point["b'StrStrIA'"] = 0

	if "b'StrStrIW'" in xk:
		point["b'StrStrIW'"] = 1
	else:
		point["b'StrStrIW'"] = 0

	if "b'StrToIntW'" in xk:
		point["b'StrToIntW'"] = 1
	else:
		point["b'StrToIntW'"] = 0

	if "b'StrTrimW'" in xk:
		point["b'StrTrimW'"] = 1
	else:
		point["b'StrTrimW'"] = 0

	if "b'StretchBlt'" in xk:
		point["b'StretchBlt'"] = 1
	else:
		point["b'StretchBlt'"] = 0

	if "b'StretchDIBits'" in xk:
		point["b'StretchDIBits'"] = 1
	else:
		point["b'StretchDIBits'"] = 0

	if "b'StringFromCLSID'" in xk:
		point["b'StringFromCLSID'"] = 1
	else:
		point["b'StringFromCLSID'"] = 0

	if "b'StringFromGUID2'" in xk:
		point["b'StringFromGUID2'"] = 1
	else:
		point["b'StringFromGUID2'"] = 0

	if "b'StrokeAndFillPath'" in xk:
		point["b'StrokeAndFillPath'"] = 1
	else:
		point["b'StrokeAndFillPath'"] = 0

	if "b'StrokePath'" in xk:
		point["b'StrokePath'"] = 1
	else:
		point["b'StrokePath'"] = 0

	if "b'SubtractRect'" in xk:
		point["b'SubtractRect'"] = 1
	else:
		point["b'SubtractRect'"] = 0

	if "b'SuspendThread'" in xk:
		point["b'SuspendThread'"] = 1
	else:
		point["b'SuspendThread'"] = 0

	if "b'SwapBuffers'" in xk:
		point["b'SwapBuffers'"] = 1
	else:
		point["b'SwapBuffers'"] = 0

	if "b'SwitchToThread'" in xk:
		point["b'SwitchToThread'"] = 1
	else:
		point["b'SwitchToThread'"] = 0

	if "b'SymCleanup'" in xk:
		point["b'SymCleanup'"] = 1
	else:
		point["b'SymCleanup'"] = 0

	if "b'SymFunctionTableAccess'" in xk:
		point["b'SymFunctionTableAccess'"] = 1
	else:
		point["b'SymFunctionTableAccess'"] = 0

	if "b'SymGetLineFromAddr'" in xk:
		point["b'SymGetLineFromAddr'"] = 1
	else:
		point["b'SymGetLineFromAddr'"] = 0

	if "b'SymGetLineFromAddr64'" in xk:
		point["b'SymGetLineFromAddr64'"] = 1
	else:
		point["b'SymGetLineFromAddr64'"] = 0

	if "b'SymGetModuleBase'" in xk:
		point["b'SymGetModuleBase'"] = 1
	else:
		point["b'SymGetModuleBase'"] = 0

	if "b'SymGetModuleInfoW'" in xk:
		point["b'SymGetModuleInfoW'"] = 1
	else:
		point["b'SymGetModuleInfoW'"] = 0

	if "b'SymGetOptions'" in xk:
		point["b'SymGetOptions'"] = 1
	else:
		point["b'SymGetOptions'"] = 0

	if "b'SymGetSymFromAddr64'" in xk:
		point["b'SymGetSymFromAddr64'"] = 1
	else:
		point["b'SymGetSymFromAddr64'"] = 0

	if "b'SymInitialize'" in xk:
		point["b'SymInitialize'"] = 1
	else:
		point["b'SymInitialize'"] = 0

	if "b'SymLoadModule64'" in xk:
		point["b'SymLoadModule64'"] = 1
	else:
		point["b'SymLoadModule64'"] = 0

	if "b'SymSetOptions'" in xk:
		point["b'SymSetOptions'"] = 1
	else:
		point["b'SymSetOptions'"] = 0

	if "b'SymSetSearchPath'" in xk:
		point["b'SymSetSearchPath'"] = 1
	else:
		point["b'SymSetSearchPath'"] = 0

	if "b'SysAllocStringLen'" in xk:
		point["b'SysAllocStringLen'"] = 1
	else:
		point["b'SysAllocStringLen'"] = 0

	if "b'SysFreeString'" in xk:
		point["b'SysFreeString'"] = 1
	else:
		point["b'SysFreeString'"] = 0

	if "b'SysReAllocStringLen'" in xk:
		point["b'SysReAllocStringLen'"] = 1
	else:
		point["b'SysReAllocStringLen'"] = 0

	if "b'SysStringLen'" in xk:
		point["b'SysStringLen'"] = 1
	else:
		point["b'SysStringLen'"] = 0

	if "b'SystemFunction025'" in xk:
		point["b'SystemFunction025'"] = 1
	else:
		point["b'SystemFunction025'"] = 0

	if "b'SystemFunction036'" in xk:
		point["b'SystemFunction036'"] = 1
	else:
		point["b'SystemFunction036'"] = 0

	if "b'SystemParametersInfoA'" in xk:
		point["b'SystemParametersInfoA'"] = 1
	else:
		point["b'SystemParametersInfoA'"] = 0

	if "b'SystemParametersInfoW'" in xk:
		point["b'SystemParametersInfoW'"] = 1
	else:
		point["b'SystemParametersInfoW'"] = 0

	if "b'SystemTimeToFileTime'" in xk:
		point["b'SystemTimeToFileTime'"] = 1
	else:
		point["b'SystemTimeToFileTime'"] = 0

	if "b'SystemTimeToTzSpecificLocalTime'" in xk:
		point["b'SystemTimeToTzSpecificLocalTime'"] = 1
	else:
		point["b'SystemTimeToTzSpecificLocalTime'"] = 0

	if "b'TabbedTextOutA'" in xk:
		point["b'TabbedTextOutA'"] = 1
	else:
		point["b'TabbedTextOutA'"] = 0

	if "b'TabbedTextOutW'" in xk:
		point["b'TabbedTextOutW'"] = 1
	else:
		point["b'TabbedTextOutW'"] = 0

	if "b'TermSession'" in xk:
		point["b'TermSession'"] = 1
	else:
		point["b'TermSession'"] = 0

	if "b'TerminateJobObject'" in xk:
		point["b'TerminateJobObject'"] = 1
	else:
		point["b'TerminateJobObject'"] = 0

	if "b'TerminateProcess'" in xk:
		point["b'TerminateProcess'"] = 1
	else:
		point["b'TerminateProcess'"] = 0

	if "b'TerminateThread'" in xk:
		point["b'TerminateThread'"] = 1
	else:
		point["b'TerminateThread'"] = 0

	if "b'TextOutA'" in xk:
		point["b'TextOutA'"] = 1
	else:
		point["b'TextOutA'"] = 0

	if "b'TextOutW'" in xk:
		point["b'TextOutW'"] = 1
	else:
		point["b'TextOutW'"] = 0

	if "b'TlsAlloc'" in xk:
		point["b'TlsAlloc'"] = 1
	else:
		point["b'TlsAlloc'"] = 0

	if "b'TlsFree'" in xk:
		point["b'TlsFree'"] = 1
	else:
		point["b'TlsFree'"] = 0

	if "b'TlsGetValue'" in xk:
		point["b'TlsGetValue'"] = 1
	else:
		point["b'TlsGetValue'"] = 0

	if "b'TlsSetValue'" in xk:
		point["b'TlsSetValue'"] = 1
	else:
		point["b'TlsSetValue'"] = 0

	if "b'ToAscii'" in xk:
		point["b'ToAscii'"] = 1
	else:
		point["b'ToAscii'"] = 0

	if "b'ToAsciiEx'" in xk:
		point["b'ToAsciiEx'"] = 1
	else:
		point["b'ToAsciiEx'"] = 0

	if "b'ToUnicode'" in xk:
		point["b'ToUnicode'"] = 1
	else:
		point["b'ToUnicode'"] = 0

	if "b'ToUnicodeEx'" in xk:
		point["b'ToUnicodeEx'"] = 1
	else:
		point["b'ToUnicodeEx'"] = 0

	if "b'Toolhelp32ReadProcessMemory'" in xk:
		point["b'Toolhelp32ReadProcessMemory'"] = 1
	else:
		point["b'Toolhelp32ReadProcessMemory'"] = 0

	if "b'TraceEvent'" in xk:
		point["b'TraceEvent'"] = 1
	else:
		point["b'TraceEvent'"] = 0

	if "b'TrackMouseEvent'" in xk:
		point["b'TrackMouseEvent'"] = 1
	else:
		point["b'TrackMouseEvent'"] = 0

	if "b'TrackPopupMenu'" in xk:
		point["b'TrackPopupMenu'"] = 1
	else:
		point["b'TrackPopupMenu'"] = 0

	if "b'TrackPopupMenuEx'" in xk:
		point["b'TrackPopupMenuEx'"] = 1
	else:
		point["b'TrackPopupMenuEx'"] = 0

	if "b'TransactNamedPipe'" in xk:
		point["b'TransactNamedPipe'"] = 1
	else:
		point["b'TransactNamedPipe'"] = 0

	if "b'TranslateAcceleratorA'" in xk:
		point["b'TranslateAcceleratorA'"] = 1
	else:
		point["b'TranslateAcceleratorA'"] = 0

	if "b'TranslateAcceleratorW'" in xk:
		point["b'TranslateAcceleratorW'"] = 1
	else:
		point["b'TranslateAcceleratorW'"] = 0

	if "b'TranslateMDISysAccel'" in xk:
		point["b'TranslateMDISysAccel'"] = 1
	else:
		point["b'TranslateMDISysAccel'"] = 0

	if "b'TranslateMessage'" in xk:
		point["b'TranslateMessage'"] = 1
	else:
		point["b'TranslateMessage'"] = 0

	if "b'TransmitCommChar'" in xk:
		point["b'TransmitCommChar'"] = 1
	else:
		point["b'TransmitCommChar'"] = 0

	if "b'TransparentBlt'" in xk:
		point["b'TransparentBlt'"] = 1
	else:
		point["b'TransparentBlt'"] = 0

	if "b'TryEnterCriticalSection'" in xk:
		point["b'TryEnterCriticalSection'"] = 1
	else:
		point["b'TryEnterCriticalSection'"] = 0

	if "b'TzSpecificLocalTimeToSystemTime'" in xk:
		point["b'TzSpecificLocalTimeToSystemTime'"] = 1
	else:
		point["b'TzSpecificLocalTimeToSystemTime'"] = 0

	if "b'URLDownloadToFileA'" in xk:
		point["b'URLDownloadToFileA'"] = 1
	else:
		point["b'URLDownloadToFileA'"] = 0

	if "b'UnhandledExceptionFilter'" in xk:
		point["b'UnhandledExceptionFilter'"] = 1
	else:
		point["b'UnhandledExceptionFilter'"] = 0

	if "b'UnhookWindowsHookEx'" in xk:
		point["b'UnhookWindowsHookEx'"] = 1
	else:
		point["b'UnhookWindowsHookEx'"] = 0

	if "b'UnionRect'" in xk:
		point["b'UnionRect'"] = 1
	else:
		point["b'UnionRect'"] = 0

	if "b'UnloadUserProfile'" in xk:
		point["b'UnloadUserProfile'"] = 1
	else:
		point["b'UnloadUserProfile'"] = 0

	if "b'UnlockFile'" in xk:
		point["b'UnlockFile'"] = 1
	else:
		point["b'UnlockFile'"] = 0

	if "b'UnlockFileEx'" in xk:
		point["b'UnlockFileEx'"] = 1
	else:
		point["b'UnlockFileEx'"] = 0

	if "b'UnlockServiceDatabase'" in xk:
		point["b'UnlockServiceDatabase'"] = 1
	else:
		point["b'UnlockServiceDatabase'"] = 0

	if "b'UnmapViewOfFile'" in xk:
		point["b'UnmapViewOfFile'"] = 1
	else:
		point["b'UnmapViewOfFile'"] = 0

	if "b'UnpackDDElParam'" in xk:
		point["b'UnpackDDElParam'"] = 1
	else:
		point["b'UnpackDDElParam'"] = 0

	if "b'UnrealizeObject'" in xk:
		point["b'UnrealizeObject'"] = 1
	else:
		point["b'UnrealizeObject'"] = 0

	if "b'UnregisterClassA'" in xk:
		point["b'UnregisterClassA'"] = 1
	else:
		point["b'UnregisterClassA'"] = 0

	if "b'UnregisterClassW'" in xk:
		point["b'UnregisterClassW'"] = 1
	else:
		point["b'UnregisterClassW'"] = 0

	if "b'UnregisterConsoleIME'" in xk:
		point["b'UnregisterConsoleIME'"] = 1
	else:
		point["b'UnregisterConsoleIME'"] = 0

	if "b'UnregisterDeviceNotification'" in xk:
		point["b'UnregisterDeviceNotification'"] = 1
	else:
		point["b'UnregisterDeviceNotification'"] = 0

	if "b'UnregisterHotKey'" in xk:
		point["b'UnregisterHotKey'"] = 1
	else:
		point["b'UnregisterHotKey'"] = 0

	if "b'UnregisterTraceGuids'" in xk:
		point["b'UnregisterTraceGuids'"] = 1
	else:
		point["b'UnregisterTraceGuids'"] = 0

	if "b'UnregisterWait'" in xk:
		point["b'UnregisterWait'"] = 1
	else:
		point["b'UnregisterWait'"] = 0

	if "b'UnregisterWaitEx'" in xk:
		point["b'UnregisterWaitEx'"] = 1
	else:
		point["b'UnregisterWaitEx'"] = 0

	if "b'UpdateLayeredWindow'" in xk:
		point["b'UpdateLayeredWindow'"] = 1
	else:
		point["b'UpdateLayeredWindow'"] = 0

	if "b'UpdateResourceA'" in xk:
		point["b'UpdateResourceA'"] = 1
	else:
		point["b'UpdateResourceA'"] = 0

	if "b'UpdateWindow'" in xk:
		point["b'UpdateWindow'"] = 1
	else:
		point["b'UpdateWindow'"] = 0

	if "b'UrlIsW'" in xk:
		point["b'UrlIsW'"] = 1
	else:
		point["b'UrlIsW'"] = 0

	if "b'UuidCreate'" in xk:
		point["b'UuidCreate'"] = 1
	else:
		point["b'UuidCreate'"] = 0

	if "b'VARIANT_UserFree'" in xk:
		point["b'VARIANT_UserFree'"] = 1
	else:
		point["b'VARIANT_UserFree'"] = 0

	if "b'ValidateRect'" in xk:
		point["b'ValidateRect'"] = 1
	else:
		point["b'ValidateRect'"] = 0

	if "b'ValidateRgn'" in xk:
		point["b'ValidateRgn'"] = 1
	else:
		point["b'ValidateRgn'"] = 0

	if "b'VarBoolFromUI1'" in xk:
		point["b'VarBoolFromUI1'"] = 1
	else:
		point["b'VarBoolFromUI1'"] = 0

	if "b'VarBstrFromI1'" in xk:
		point["b'VarBstrFromI1'"] = 1
	else:
		point["b'VarBstrFromI1'"] = 0

	if "b'VarR8FromI1'" in xk:
		point["b'VarR8FromI1'"] = 1
	else:
		point["b'VarR8FromI1'"] = 0

	if "b'VarUI8FromDec'" in xk:
		point["b'VarUI8FromDec'"] = 1
	else:
		point["b'VarUI8FromDec'"] = 0

	if "b'VarUI8FromUI2'" in xk:
		point["b'VarUI8FromUI2'"] = 1
	else:
		point["b'VarUI8FromUI2'"] = 0

	if "b'VariantChangeType'" in xk:
		point["b'VariantChangeType'"] = 1
	else:
		point["b'VariantChangeType'"] = 0

	if "b'VariantChangeTypeEx'" in xk:
		point["b'VariantChangeTypeEx'"] = 1
	else:
		point["b'VariantChangeTypeEx'"] = 0

	if "b'VariantClear'" in xk:
		point["b'VariantClear'"] = 1
	else:
		point["b'VariantClear'"] = 0

	if "b'VariantCopy'" in xk:
		point["b'VariantCopy'"] = 1
	else:
		point["b'VariantCopy'"] = 0

	if "b'VariantCopyInd'" in xk:
		point["b'VariantCopyInd'"] = 1
	else:
		point["b'VariantCopyInd'"] = 0

	if "b'VariantInit'" in xk:
		point["b'VariantInit'"] = 1
	else:
		point["b'VariantInit'"] = 0

	if "b'VerLanguageNameA'" in xk:
		point["b'VerLanguageNameA'"] = 1
	else:
		point["b'VerLanguageNameA'"] = 0

	if "b'VerQueryValueA'" in xk:
		point["b'VerQueryValueA'"] = 1
	else:
		point["b'VerQueryValueA'"] = 0

	if "b'VerQueryValueW'" in xk:
		point["b'VerQueryValueW'"] = 1
	else:
		point["b'VerQueryValueW'"] = 0

	if "b'VerSetConditionMask'" in xk:
		point["b'VerSetConditionMask'"] = 1
	else:
		point["b'VerSetConditionMask'"] = 0

	if "b'VerifyConsoleIoHandle'" in xk:
		point["b'VerifyConsoleIoHandle'"] = 1
	else:
		point["b'VerifyConsoleIoHandle'"] = 0

	if "b'VerifyVersionInfoW'" in xk:
		point["b'VerifyVersionInfoW'"] = 1
	else:
		point["b'VerifyVersionInfoW'"] = 0

	if "b'VirtualAlloc'" in xk:
		point["b'VirtualAlloc'"] = 1
	else:
		point["b'VirtualAlloc'"] = 0

	if "b'VirtualAllocEx'" in xk:
		point["b'VirtualAllocEx'"] = 1
	else:
		point["b'VirtualAllocEx'"] = 0

	if "b'VirtualFree'" in xk:
		point["b'VirtualFree'"] = 1
	else:
		point["b'VirtualFree'"] = 0

	if "b'VirtualFreeEx'" in xk:
		point["b'VirtualFreeEx'"] = 1
	else:
		point["b'VirtualFreeEx'"] = 0

	if "b'VirtualLock'" in xk:
		point["b'VirtualLock'"] = 1
	else:
		point["b'VirtualLock'"] = 0

	if "b'VirtualProtect'" in xk:
		point["b'VirtualProtect'"] = 1
	else:
		point["b'VirtualProtect'"] = 0

	if "b'VirtualProtectEx'" in xk:
		point["b'VirtualProtectEx'"] = 1
	else:
		point["b'VirtualProtectEx'"] = 0

	if "b'VirtualQuery'" in xk:
		point["b'VirtualQuery'"] = 1
	else:
		point["b'VirtualQuery'"] = 0

	if "b'VirtualQueryEx'" in xk:
		point["b'VirtualQueryEx'"] = 1
	else:
		point["b'VirtualQueryEx'"] = 0

	if "b'VirtualUnlock'" in xk:
		point["b'VirtualUnlock'"] = 1
	else:
		point["b'VirtualUnlock'"] = 0

	if "b'VkKeyScanA'" in xk:
		point["b'VkKeyScanA'"] = 1
	else:
		point["b'VkKeyScanA'"] = 0

	if "b'VkKeyScanW'" in xk:
		point["b'VkKeyScanW'"] = 1
	else:
		point["b'VkKeyScanW'"] = 0

	if "b'WINNLSGetEnableStatus'" in xk:
		point["b'WINNLSGetEnableStatus'"] = 1
	else:
		point["b'WINNLSGetEnableStatus'"] = 0

	if "b'WNetAddConnection2A'" in xk:
		point["b'WNetAddConnection2A'"] = 1
	else:
		point["b'WNetAddConnection2A'"] = 0

	if "b'WNetAddConnection2W'" in xk:
		point["b'WNetAddConnection2W'"] = 1
	else:
		point["b'WNetAddConnection2W'"] = 0

	if "b'WNetCancelConnection2A'" in xk:
		point["b'WNetCancelConnection2A'"] = 1
	else:
		point["b'WNetCancelConnection2A'"] = 0

	if "b'WNetCancelConnection2W'" in xk:
		point["b'WNetCancelConnection2W'"] = 1
	else:
		point["b'WNetCancelConnection2W'"] = 0

	if "b'WNetCloseEnum'" in xk:
		point["b'WNetCloseEnum'"] = 1
	else:
		point["b'WNetCloseEnum'"] = 0

	if "b'WNetEnumResourceA'" in xk:
		point["b'WNetEnumResourceA'"] = 1
	else:
		point["b'WNetEnumResourceA'"] = 0

	if "b'WNetEnumResourceW'" in xk:
		point["b'WNetEnumResourceW'"] = 1
	else:
		point["b'WNetEnumResourceW'"] = 0

	if "b'WNetGetConnectionW'" in xk:
		point["b'WNetGetConnectionW'"] = 1
	else:
		point["b'WNetGetConnectionW'"] = 0

	if "b'WNetOpenEnumA'" in xk:
		point["b'WNetOpenEnumA'"] = 1
	else:
		point["b'WNetOpenEnumA'"] = 0

	if "b'WNetOpenEnumW'" in xk:
		point["b'WNetOpenEnumW'"] = 1
	else:
		point["b'WNetOpenEnumW'"] = 0

	if "b'WNetUseConnectionW'" in xk:
		point["b'WNetUseConnectionW'"] = 1
	else:
		point["b'WNetUseConnectionW'"] = 0

	if "b'WOWShellExecute'" in xk:
		point["b'WOWShellExecute'"] = 1
	else:
		point["b'WOWShellExecute'"] = 0

	if "b'WSACleanup'" in xk:
		point["b'WSACleanup'"] = 1
	else:
		point["b'WSACleanup'"] = 0

	if "b'WSAEnumNetworkEvents'" in xk:
		point["b'WSAEnumNetworkEvents'"] = 1
	else:
		point["b'WSAEnumNetworkEvents'"] = 0

	if "b'WSAGetLastError'" in xk:
		point["b'WSAGetLastError'"] = 1
	else:
		point["b'WSAGetLastError'"] = 0

	if "b'WSAGetServiceClassNameByClassIdW'" in xk:
		point["b'WSAGetServiceClassNameByClassIdW'"] = 1
	else:
		point["b'WSAGetServiceClassNameByClassIdW'"] = 0

	if "b'WSAIoctl'" in xk:
		point["b'WSAIoctl'"] = 1
	else:
		point["b'WSAIoctl'"] = 0

	if "b'WSAStartup'" in xk:
		point["b'WSAStartup'"] = 1
	else:
		point["b'WSAStartup'"] = 0

	if "b'WTSGetActiveConsoleSessionId'" in xk:
		point["b'WTSGetActiveConsoleSessionId'"] = 1
	else:
		point["b'WTSGetActiveConsoleSessionId'"] = 0

	if "b'WTSQueryUserToken'" in xk:
		point["b'WTSQueryUserToken'"] = 1
	else:
		point["b'WTSQueryUserToken'"] = 0

	if "b'WaitForDebugEvent'" in xk:
		point["b'WaitForDebugEvent'"] = 1
	else:
		point["b'WaitForDebugEvent'"] = 0

	if "b'WaitForInputIdle'" in xk:
		point["b'WaitForInputIdle'"] = 1
	else:
		point["b'WaitForInputIdle'"] = 0

	if "b'WaitForMultipleObjects'" in xk:
		point["b'WaitForMultipleObjects'"] = 1
	else:
		point["b'WaitForMultipleObjects'"] = 0

	if "b'WaitForMultipleObjectsEx'" in xk:
		point["b'WaitForMultipleObjectsEx'"] = 1
	else:
		point["b'WaitForMultipleObjectsEx'"] = 0

	if "b'WaitForSingleObject'" in xk:
		point["b'WaitForSingleObject'"] = 1
	else:
		point["b'WaitForSingleObject'"] = 0

	if "b'WaitForSingleObjectEx'" in xk:
		point["b'WaitForSingleObjectEx'"] = 1
	else:
		point["b'WaitForSingleObjectEx'"] = 0

	if "b'WaitMessage'" in xk:
		point["b'WaitMessage'"] = 1
	else:
		point["b'WaitMessage'"] = 0

	if "b'WaitNamedPipeA'" in xk:
		point["b'WaitNamedPipeA'"] = 1
	else:
		point["b'WaitNamedPipeA'"] = 0

	if "b'WaitNamedPipeW'" in xk:
		point["b'WaitNamedPipeW'"] = 1
	else:
		point["b'WaitNamedPipeW'"] = 0

	if "b'WideCharToMultiByte'" in xk:
		point["b'WideCharToMultiByte'"] = 1
	else:
		point["b'WideCharToMultiByte'"] = 0

	if "b'WidenPath'" in xk:
		point["b'WidenPath'"] = 1
	else:
		point["b'WidenPath'"] = 0

	if "b'WinExec'" in xk:
		point["b'WinExec'"] = 1
	else:
		point["b'WinExec'"] = 0

	if "b'WinHelpA'" in xk:
		point["b'WinHelpA'"] = 1
	else:
		point["b'WinHelpA'"] = 0

	if "b'WinHelpW'" in xk:
		point["b'WinHelpW'"] = 1
	else:
		point["b'WinHelpW'"] = 0

	if "b'WinHttpReceiveResponse'" in xk:
		point["b'WinHttpReceiveResponse'"] = 1
	else:
		point["b'WinHttpReceiveResponse'"] = 0

	if "b'WinVerifyTrust'" in xk:
		point["b'WinVerifyTrust'"] = 1
	else:
		point["b'WinVerifyTrust'"] = 0

	if "b'WindowFromDC'" in xk:
		point["b'WindowFromDC'"] = 1
	else:
		point["b'WindowFromDC'"] = 0

	if "b'WindowFromPoint'" in xk:
		point["b'WindowFromPoint'"] = 1
	else:
		point["b'WindowFromPoint'"] = 0

	if "b'WriteConsoleA'" in xk:
		point["b'WriteConsoleA'"] = 1
	else:
		point["b'WriteConsoleA'"] = 0

	if "b'WriteConsoleW'" in xk:
		point["b'WriteConsoleW'"] = 1
	else:
		point["b'WriteConsoleW'"] = 0

	if "b'WriteConsoleInputW'" in xk:
		point["b'WriteConsoleInputW'"] = 1
	else:
		point["b'WriteConsoleInputW'"] = 0

	if "b'WriteConsoleOutputA'" in xk:
		point["b'WriteConsoleOutputA'"] = 1
	else:
		point["b'WriteConsoleOutputA'"] = 0

	if "b'WriteConsoleOutputCharacterW'" in xk:
		point["b'WriteConsoleOutputCharacterW'"] = 1
	else:
		point["b'WriteConsoleOutputCharacterW'"] = 0

	if "b'WriteFile'" in xk:
		point["b'WriteFile'"] = 1
	else:
		point["b'WriteFile'"] = 0

	if "b'WriteFileEx'" in xk:
		point["b'WriteFileEx'"] = 1
	else:
		point["b'WriteFileEx'"] = 0

	if "b'WriteFileGather'" in xk:
		point["b'WriteFileGather'"] = 1
	else:
		point["b'WriteFileGather'"] = 0

	if "b'WritePrivateProfileSectionA'" in xk:
		point["b'WritePrivateProfileSectionA'"] = 1
	else:
		point["b'WritePrivateProfileSectionA'"] = 0

	if "b'WritePrivateProfileSectionW'" in xk:
		point["b'WritePrivateProfileSectionW'"] = 1
	else:
		point["b'WritePrivateProfileSectionW'"] = 0

	if "b'WritePrivateProfileStringA'" in xk:
		point["b'WritePrivateProfileStringA'"] = 1
	else:
		point["b'WritePrivateProfileStringA'"] = 0

	if "b'WritePrivateProfileStringW'" in xk:
		point["b'WritePrivateProfileStringW'"] = 1
	else:
		point["b'WritePrivateProfileStringW'"] = 0

	if "b'WritePrivateProfileStructA'" in xk:
		point["b'WritePrivateProfileStructA'"] = 1
	else:
		point["b'WritePrivateProfileStructA'"] = 0

	if "b'WriteProcessMemory'" in xk:
		point["b'WriteProcessMemory'"] = 1
	else:
		point["b'WriteProcessMemory'"] = 0

	if "b'WriteProfileSectionW'" in xk:
		point["b'WriteProfileSectionW'"] = 1
	else:
		point["b'WriteProfileSectionW'"] = 0

	if "b'XLATEOBJ_piVector'" in xk:
		point["b'XLATEOBJ_piVector'"] = 1
	else:
		point["b'XLATEOBJ_piVector'"] = 0

	if "b'ZwAllocateVirtualMemory'" in xk:
		point["b'ZwAllocateVirtualMemory'"] = 1
	else:
		point["b'ZwAllocateVirtualMemory'"] = 0

	if "b'ZwClose'" in xk:
		point["b'ZwClose'"] = 1
	else:
		point["b'ZwClose'"] = 0

	if "b'ZwCreateFile'" in xk:
		point["b'ZwCreateFile'"] = 1
	else:
		point["b'ZwCreateFile'"] = 0

	if "b'ZwDeleteValueKey'" in xk:
		point["b'ZwDeleteValueKey'"] = 1
	else:
		point["b'ZwDeleteValueKey'"] = 0

	if "b'ZwImpersonateClientOfPort'" in xk:
		point["b'ZwImpersonateClientOfPort'"] = 1
	else:
		point["b'ZwImpersonateClientOfPort'"] = 0

	if "b'ZwLoadKey2'" in xk:
		point["b'ZwLoadKey2'"] = 1
	else:
		point["b'ZwLoadKey2'"] = 0

	if "b'ZwOpenFile'" in xk:
		point["b'ZwOpenFile'"] = 1
	else:
		point["b'ZwOpenFile'"] = 0

	if "b'ZwOpenKey'" in xk:
		point["b'ZwOpenKey'"] = 1
	else:
		point["b'ZwOpenKey'"] = 0

	if "b'ZwQueryInformationFile'" in xk:
		point["b'ZwQueryInformationFile'"] = 1
	else:
		point["b'ZwQueryInformationFile'"] = 0

	if "b'ZwQueryInformationProcess'" in xk:
		point["b'ZwQueryInformationProcess'"] = 1
	else:
		point["b'ZwQueryInformationProcess'"] = 0

	if "b'ZwQuerySystemInformation'" in xk:
		point["b'ZwQuerySystemInformation'"] = 1
	else:
		point["b'ZwQuerySystemInformation'"] = 0

	if "b'ZwQueryValueKey'" in xk:
		point["b'ZwQueryValueKey'"] = 1
	else:
		point["b'ZwQueryValueKey'"] = 0

	if "b'ZwReadFile'" in xk:
		point["b'ZwReadFile'"] = 1
	else:
		point["b'ZwReadFile'"] = 0

	if "b'ZwSetHighWaitLowEventPair'" in xk:
		point["b'ZwSetHighWaitLowEventPair'"] = 1
	else:
		point["b'ZwSetHighWaitLowEventPair'"] = 0

	if "b'accept'" in xk:
		point["b'accept'"] = 1
	else:
		point["b'accept'"] = 0

	if "b'bind'" in xk:
		point["b'bind'"] = 1
	else:
		point["b'bind'"] = 0

	if "b'closesocket'" in xk:
		point["b'closesocket'"] = 1
	else:
		point["b'closesocket'"] = 0

	if "b'connect'" in xk:
		point["b'connect'"] = 1
	else:
		point["b'connect'"] = 0

	if "b'gethostbyaddr'" in xk:
		point["b'gethostbyaddr'"] = 1
	else:
		point["b'gethostbyaddr'"] = 0

	if "b'gethostbyname'" in xk:
		point["b'gethostbyname'"] = 1
	else:
		point["b'gethostbyname'"] = 0

	if "b'getservbyname'" in xk:
		point["b'getservbyname'"] = 1
	else:
		point["b'getservbyname'"] = 0

	if "b'getsockname'" in xk:
		point["b'getsockname'"] = 1
	else:
		point["b'getsockname'"] = 0

	if "b'htons'" in xk:
		point["b'htons'"] = 1
	else:
		point["b'htons'"] = 0

	if "b'inet_addr'" in xk:
		point["b'inet_addr'"] = 1
	else:
		point["b'inet_addr'"] = 0

	if "b'inet_ntoa'" in xk:
		point["b'inet_ntoa'"] = 1
	else:
		point["b'inet_ntoa'"] = 0

	if "b'listen'" in xk:
		point["b'listen'"] = 1
	else:
	 	point["b'listen'"] = 0

	if "b'recv'" in xk:
	 	point["b'recv'"] = 1
	else:
	 	point["b'recv'"] = 0

	if "b'send'" in xk:
		point["b'send'"] = 1
	else:
		point["b'send'"] = 0

	if "b'socket'" in xk:
		point["b'socket'"] = 1
	else:
		point["b'socket'"] = 0

	return point