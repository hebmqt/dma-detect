#include "help.h"

// Known patterns for cheating devices
const std::vector<std::string> KMBOX_PATTERNS = {
    "VID_1A2C&PID_2124",      
    "VID_1A2C&PID_21",        
    "VID_1A86&PID_E026",      
    "KMBOX",                  
    "KEYBOARD_MOUSE_BOX"   
};

const std::vector<std::string> FUZER_PATTERNS = {
    "VID_0483&PID_5750",      
    "VID_0483&PID_5740",      
    "FUZER",                  
    "STM32",                  
    "DFU_INTERFACE"           
};

const std::vector<std::string> DMA_PATTERNS = {
    "PCI\\CC_0800",           
    "PCI\\CC_0880",      
    "THUNDERBOLT",         
    "PCIEXPRESS",             
    "FPGA",                   
    "ACCELE",                 
    "SYSTEM_PERIPHERAL"     
};

// Structure for device information
struct DeviceInfo {
    std::string deviceId;
    std::string description;
    std::string hardwareIds;
    bool isSuspicious;
    std::string detectionReason;
};

// Convert wide string to string
std::string WideToMultiByte(const wchar_t* wideStr) {
    if (!wideStr) return "";

    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    if (bufferSize == 0) return "";

    std::string result(bufferSize, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &result[0], bufferSize, nullptr, nullptr);

    // Remove null terminator
    if (!result.empty() && result[result.size() - 1] == '\0') {
        result.pop_back();
    }

    return result;
}

// Convert string to uppercase
std::string ToUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

// Check if string contains any of the patterns
bool ContainsPattern(const std::string& text, const std::vector<std::string>& patterns) {
    std::string upperText = ToUpper(text);

    for (const auto& pattern : patterns) {
        if (upperText.find(ToUpper(pattern)) != std::string::npos) {
            return true;
        }
    }

    return false;
}

// Get device property
std::string GetDeviceProperty(HDEVINFO hDevInfo, SP_DEVINFO_DATA& devInfoData, DWORD property) {
    DWORD dataType = 0;
    DWORD requiredSize = 0;

    // Get required buffer size
    SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, property,
        &dataType, nullptr, 0, &requiredSize);

    if (requiredSize == 0) {
        return "";
    }

    std::vector<wchar_t> buffer(requiredSize / sizeof(wchar_t) + 1, 0);

    if (!SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, property,
        &dataType, reinterpret_cast<PBYTE>(buffer.data()),
        requiredSize, nullptr)) {
        return "";
    }

    return WideToMultiByte(buffer.data());
}

// Get device hardware IDs
std::string GetDeviceHardwareIds(HDEVINFO hDevInfo, SP_DEVINFO_DATA& devInfoData) {
    DWORD requiredSize = 0;

    SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_HARDWAREID,
        nullptr, nullptr, 0, &requiredSize);

    if (requiredSize == 0) {
        return "";
    }

    std::vector<wchar_t> buffer(requiredSize / sizeof(wchar_t) + 1, 0);

    if (!SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_HARDWAREID,
        nullptr, reinterpret_cast<PBYTE>(buffer.data()),
        requiredSize, nullptr)) {
        return "";
    }

    std::string result;
    const wchar_t* current = buffer.data();

    while (*current) {
        if (!result.empty()) {
            result += ";";
        }
        result += WideToMultiByte(current);
        current += wcslen(current) + 1;
    }

    return result;
}

// Scan for suspicious devices
std::vector<DeviceInfo> ScanForSuspiciousDevices() {
    std::vector<DeviceInfo> suspiciousDevices;

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(nullptr, nullptr, nullptr,
        DIGCF_ALLCLASSES | DIGCF_PRESENT);

    if (hDevInfo == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to get device information." << std::endl;
        return suspiciousDevices;
    }

    SP_DEVINFO_DATA devInfoData;
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        DeviceInfo device;

        device.deviceId = GetDeviceProperty(hDevInfo, devInfoData, SPDRP_HARDWAREID);
        device.description = GetDeviceProperty(hDevInfo, devInfoData, SPDRP_DEVICEDESC);
        device.hardwareIds = GetDeviceHardwareIds(hDevInfo, devInfoData);

        // Check for KMBox patterns
        if (ContainsPattern(device.hardwareIds, KMBOX_PATTERNS) ||
            ContainsPattern(device.description, KMBOX_PATTERNS)) {
            device.isSuspicious = true;
            device.detectionReason = "[$] KMBox pattern detected";
            suspiciousDevices.push_back(device);
            continue;
        }

        // Check for Fuzer patterns
        if (ContainsPattern(device.hardwareIds, FUZER_PATTERNS) ||
            ContainsPattern(device.description, FUZER_PATTERNS)) {
            device.isSuspicious = true;
            device.detectionReason = "[$] Fuzer pattern detected";
            suspiciousDevices.push_back(device);
            continue;
        }

        // Check for DMA patterns
        if (ContainsPattern(device.hardwareIds, DMA_PATTERNS) ||
            ContainsPattern(device.description, DMA_PATTERNS)) {
            device.isSuspicious = true;
            device.detectionReason = "[$] DMA-capable device detected";
            suspiciousDevices.push_back(device);
        }
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    return suspiciousDevices;
}

void ShowBanner() {
    std::cout << " DMA Scanning Application" << std::endl;
    std::cout << "                         @ github.com/hebmqt" << std::endl;
    std::cout << std::endl;
}

int main() {
    ShowBanner();

    // Get user consent
    std::cout << "Do you agree to the system scan? (yes/no): ";
    std::string agreement;
    std::cin >> agreement;

    if (agreement != "yes" && agreement != "y") {
        std::cout << "Scan aborted. You must agree to proceed." << std::endl;
        return 0;
    }

    std::cout << "[!] Starting device scan..." << std::endl;

    // Scan for suspicious devices
    std::vector<DeviceInfo> suspiciousDevices = ScanForSuspiciousDevices();

    // Display results
    std::cout << "\nScan completed." << std::endl;
    std::cout << "Found " << suspiciousDevices.size() << " suspicious devices:" << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    for (const auto& device : suspiciousDevices) {
        std::cout << "Device: " << device.description << std::endl;
        std::cout << "Reason: " << device.detectionReason << std::endl;
        std::cout << "Hardware IDs: " << device.hardwareIds << std::endl;
        std::cout << "----------------------------------------" << std::endl;
    }

    if (suspiciousDevices.empty()) {
        std::cout << "No suspicious devices detected." << std::endl;
    }

    std::cout << "\nScan completed. Press any key to exit." << std::endl;
    std::cin.ignore();
    std::cin.get();

    return 0;
}