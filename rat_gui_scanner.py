import os
import re
import zipfile
import tempfile
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading

# Try different import methods for androguard
try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.analysis.analysis import Analysis
    from androguard.core.bytecodes.dvm import DalvikVMFormat
except ImportError as e:
    print(f"Androguard import error: {e}")
    print("Please install androguard using: pip install androguard")
    exit(1)

def validate_apk_file(file_path):
    """Validate if the file is a proper APK"""
    try:
        # Check if file exists and is readable
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        if not os.path.isfile(file_path):
            return False, "Path is not a file"
        
        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return False, "File is empty"
        
        # Check if it's a valid ZIP file (APK is a ZIP archive)
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                # Check for AndroidManifest.xml (required in APK)
                if 'AndroidManifest.xml' not in zip_file.namelist():
                    return False, "Not a valid APK file (missing AndroidManifest.xml)"
        except zipfile.BadZipFile:
            return False, "File is not a valid ZIP/APK archive"
        
        return True, "Valid APK file"
    
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def simple_apk_info(file_path):
    """Get basic APK info without full androguard analysis"""
    try:
        normalized_path = os.path.normpath(file_path)
        
        # Try simple ZIP-based analysis first
        with zipfile.ZipFile(normalized_path, 'r') as zip_file:
            files = zip_file.namelist()
            
        info = f"📦 APK File: {os.path.basename(file_path)}\n"
        info += f"📁 File Size: {os.path.getsize(file_path) / (1024*1024):.1f} MB\n"
        info += f"🗂️ Internal Files: {len(files)}\n"
        
        # Check for common files
        common_files = ['AndroidManifest.xml', 'classes.dex', 'resources.arsc']
        info += "\n📋 Key Files Present:\n"
        for cf in common_files:
            status = "✅" if cf in files else "❌"
            info += f"  {status} {cf}\n"
        
        return info
        
    except Exception as e:
        return f"❌ Error getting basic info: {str(e)}\n"

# Suspicious permissions list
SUSPICIOUS_PERMISSIONS = [
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.DEVICE_ADMIN",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.WAKE_LOCK",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.WRITE_SETTINGS",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.MODIFY_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS",
]

# Map permissions to API patterns
PERMISSION_APIS = {
    "android.permission.RECORD_AUDIO": [
        r"MediaRecorder",
        r"AudioRecord",
        r"startRecording",
        r"setAudioSource"
    ],
    "android.permission.CAMERA": [
        r"Camera\.open",
        r"camera2",
        r"CameraManager",
        r"takePicture"
    ],
    "android.permission.SEND_SMS": [
        r"SmsManager",
        r"sendTextMessage",
        r"sendMultipartTextMessage"
    ],
    "android.permission.READ_SMS": [
        r"content://sms",
        r"Telephony\.Sms",
        r"getMessages"
    ],
    "android.permission.CALL_PHONE": [
        r"Intent\.ACTION_CALL",
        r"TelecomManager",
        r"tel:"
    ],
    "android.permission.ACCESS_FINE_LOCATION": [
        r"LocationManager",
        r"FusedLocationProviderClient",
        r"getLastKnownLocation",
        r"requestLocationUpdates"
    ],
    "android.permission.READ_CONTACTS": [
        r"ContactsContract",
        r"content://contacts",
        r"getContentResolver"
    ],
    "android.permission.READ_EXTERNAL_STORAGE": [
        r"getExternalStorage",
        r"Environment\.getExternalStorageDirectory",
        r"MediaStore"
    ],
    "android.permission.WRITE_EXTERNAL_STORAGE": [
        r"getExternalStorage",
        r"Environment\.getExternalStorageDirectory",
        r"FileOutputStream"
    ],
    "android.permission.INTERNET": [
        r"HttpURLConnection",
        r"Socket",
        r"URL",
        r"OkHttp"
    ],
}

def check_api_usage(apk_path, permissions):
    """Check if permissions are actually used by analyzing the APK's code"""
    unused = []
    used = []
    
    try:
        # Load APK with better error handling
        normalized_path = os.path.normpath(apk_path)
        try:
            apk = APK(normalized_path)
        except Exception:
            # Try with raw bytes
            with open(normalized_path, 'rb') as f:
                apk_data = f.read()
            apk = APK(apk_data, raw=True)
        
        # Get all DEX files
        dex_files = []
        for dex in apk.get_all_dex():
            dvm = DalvikVMFormat(dex)
            dex_files.append(dvm)
        
        # Analyze the code
        analysis = Analysis()
        for dvm in dex_files:
            analysis.add(dvm)
        analysis.create_xref()
        
        # Check each permission
        for perm in permissions:
            if perm in PERMISSION_APIS:
                found = False
                api_patterns = PERMISSION_APIS[perm]
                
                # Search through all classes and methods
                for dvm in dex_files:
                    for class_obj in dvm.get_classes():
                        class_name = class_obj.get_name()
                        
                        # Check class name
                        for pattern in api_patterns:
                            if re.search(pattern, class_name, re.IGNORECASE):
                                found = True
                                break
                        
                        if found:
                            break
                        
                        # Check methods
                        for method in class_obj.get_methods():
                            method_name = method.get_name()
                            
                            for pattern in api_patterns:
                                if re.search(pattern, method_name, re.IGNORECASE):
                                    found = True
                                    break
                            
                            if found:
                                break
                        
                        if found:
                            break
                    
                    if found:
                        break
                
                if found:
                    used.append(perm)
                else:
                    unused.append(perm)
            else:
                # If we don't have API patterns for this permission, assume it's used
                used.append(perm)
                
    except Exception as e:
        unused.append(f"Error analyzing API usage: {str(e)}")
    
    return unused, used

def scan_apk(apk_path, progress_callback=None):
    """Scan APK file and return analysis results"""
    result = ""
    
    try:
        # Validate file path and existence
        if not os.path.exists(apk_path):
            return f"❌ Error: File does not exist: {apk_path}\n"
        
        if not os.path.isfile(apk_path):
            return f"❌ Error: Path is not a file: {apk_path}\n"
        
        # Check file size
        file_size = os.path.getsize(apk_path)
        if file_size == 0:
            return f"❌ Error: File is empty: {apk_path}\n"
        
        # Normalize path (handle Windows paths)
        normalized_path = os.path.normpath(apk_path)
        
        if progress_callback:
            progress_callback(f"Loading APK... (Size: {file_size / (1024*1024):.1f} MB)")
        
        # Try to load the APK with better error handling
        try:
            apk = APK(normalized_path)
        except Exception as apk_error:
            # Try with raw bytes if path fails
            try:
                with open(normalized_path, 'rb') as f:
                    apk_data = f.read()
                apk = APK(apk_data, raw=True)
            except Exception as raw_error:
                return f"❌ Error loading APK: {str(apk_error)}\n❌ Raw load also failed: {str(raw_error)}\n"
        
        # Basic info
        app_name = apk.get_app_name() or "Unknown"
        package_name = apk.get_package() or "Unknown"
        main_activity = apk.get_main_activity() or "Unknown"
        permissions = apk.get_permissions()
        
        # Find suspicious permissions
        suspicious = [p for p in permissions if p in SUSPICIOUS_PERMISSIONS]
        
        if progress_callback:
            progress_callback("Analyzing API usage...")
        
        # Check for unused permissions
        unused, used = check_api_usage(apk_path, permissions)
        
        # Format results
        result += f"📦 APK File: {os.path.basename(apk_path)}\n"
        result += f"🏷️ App Name: {app_name}\n"
        result += f"📦 Package: {package_name}\n"
        result += f"🎯 Main Activity: {main_activity}\n"
        result += f"🔢 Total Permissions: {len(permissions)}\n\n"
        
        result += "⚠️ SUSPICIOUS PERMISSIONS:\n"
        if suspicious:
            for perm in suspicious:
                status = "✅ USED" if perm in used else "❌ UNUSED"
                result += f"  - {perm} [{status}]\n"
        else:
            result += "  ✅ None Detected\n"
        
        result += "\n🚨 POTENTIALLY UNUSED PERMISSIONS:\n"
        if unused and not any("Error" in str(u) for u in unused):
            for perm in unused:
                if perm in SUSPICIOUS_PERMISSIONS:
                    result += f"  - {perm} ⚠️ SUSPICIOUS\n"
                else:
                    result += f"  - {perm}\n"
        elif any("Error" in str(u) for u in unused):
            for error in unused:
                if "Error" in str(error):
                    result += f"  - {error}\n"
        else:
            result += "  ✅ All declared permissions appear to be used\n"
        
        result += "\n📋 ALL PERMISSIONS:\n"
        for perm in sorted(permissions):
            if perm in suspicious:
                result += f"  - {perm} ⚠️\n"
            else:
                result += f"  - {perm}\n"
        
        # Additional security checks
        result += "\n🔍 ADDITIONAL SECURITY CHECKS:\n"
        
        # Check for common RAT indicators
        rat_indicators = []
        if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
            rat_indicators.append("Can draw over other apps")
        if "android.permission.DEVICE_ADMIN" in permissions:
            rat_indicators.append("Has device admin privileges")
        if "android.permission.RECEIVE_BOOT_COMPLETED" in permissions:
            rat_indicators.append("Starts on boot")
        if "android.permission.DISABLE_KEYGUARD" in permissions:
            rat_indicators.append("Can disable screen lock")
        if "android.permission.WRITE_SETTINGS" in permissions:
            rat_indicators.append("Can modify system settings")
        
        if rat_indicators:
            for indicator in rat_indicators:
                result += f"  ⚠️ {indicator}\n"
        else:
            result += "  ✅ No obvious RAT indicators found\n"
        
        # Certificate info
        try:
            if progress_callback:
                progress_callback("Checking certificate...")
            
            certificates = apk.get_certificates()
            if certificates:
                result += "\n🔐 CERTIFICATE INFO:\n"
                for cert in certificates:
                    result += f"  - Subject: {cert.subject}\n"
                    result += f"  - Issuer: {cert.issuer}\n"
                    result += f"  - Valid from: {cert.not_valid_before}\n"
                    result += f"  - Valid until: {cert.not_valid_after}\n"
        except Exception as cert_error:
            result += f"\n🔐 Certificate analysis failed: {str(cert_error)}\n"
        
    except Exception as e:
        result += f"❌ Error scanning APK: {str(e)}\n"
        result += f"Make sure androguard is properly installed and the APK file is valid.\n"
    
    return result

def browse_file():
    """Handle file browsing and scanning"""
    file_path = filedialog.askopenfilename(
        title="Select APK File",
        filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
    )
    
    if file_path:
        # Clear output
        output.delete('1.0', tk.END)
        output.insert(tk.END, "🔍 Validating APK file...\n")
        root.update()
        
        # First validate the APK file
        is_valid, validation_msg = validate_apk_file(file_path)
        
        if not is_valid:
            output.insert(tk.END, f"❌ Validation failed: {validation_msg}\n\n")
            output.insert(tk.END, "📋 Basic file info:\n")
            basic_info = simple_apk_info(file_path)
            output.insert(tk.END, basic_info)
            return
        
        output.insert(tk.END, f"✅ {validation_msg}\n")
        output.insert(tk.END, "🔍 Starting detailed analysis...\n")
        root.update()
        
        # Run scan in separate thread to prevent UI freezing
        def scan_thread():
            try:
                def progress_update(message):
                    output.insert(tk.END, f"📊 {message}\n")
                    root.update()
                
                result = scan_apk(file_path, progress_update)
                
                # Update UI in main thread
                root.after(0, lambda: update_output(result))
            except Exception as e:
                error_msg = f"❌ Scanning failed: {str(e)}\n"
                error_msg += "\n📋 Basic file info:\n"
                error_msg += simple_apk_info(file_path)
                root.after(0, lambda: update_output(error_msg))
        
        def update_output(result):
            # Don't clear - append to existing validation info
            output.insert(tk.END, "\n" + "="*50 + "\n")
            output.insert(tk.END, result)
        
        # Start scanning thread
        scan_thread = threading.Thread(target=scan_thread, daemon=True)
        scan_thread.start()

def show_about():
    """Show about dialog"""
    about_text = """
Android APK Permission Scanner v2.0

This tool analyzes Android APK files to detect:
- Suspicious permissions that could indicate malware
- Unused permissions that might be over-privileged
- Common RAT (Remote Access Trojan) indicators
- Certificate information

Requires: androguard library
Install with: pip install androguard

Features:
✓ Comprehensive permission analysis
✓ API usage detection
✓ RAT behavior indicators
✓ Certificate validation
✓ File integrity checking
    """
    messagebox.showinfo("About", about_text.strip())

def export_results():
    """Export scan results to file"""
    content = output.get('1.0', tk.END)
    if content.strip():
        file_path = filedialog.asksaveasfilename(
            title="Save Scan Results",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Export", f"Results saved to: {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save file: {str(e)}")
    else:
        messagebox.showwarning("Export", "No results to export. Please scan an APK first.")

# GUI Setup
root = tk.Tk()
root.title("Android APK Permission Scanner v2.0")
root.geometry("900x700")
root.resizable(True, True)

# Menu bar
menubar = tk.Menu(root)
root.config(menu=menubar)

file_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Open APK", command=browse_file)
file_menu.add_separator()
file_menu.add_command(label="Export Results", command=export_results)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)

help_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="About", command=show_about)

# Main frame
main_frame = tk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Control frame
control_frame = tk.Frame(main_frame)
control_frame.pack(fill=tk.X, pady=(0, 10))

# Browse button
browse_btn = tk.Button(
    control_frame, 
    text="📂 Browse APK File", 
    command=browse_file, 
    font=("Arial", 12, "bold"), 
    bg="#007acc", 
    fg="white", 
    padx=20, 
    pady=10,
    cursor="hand2"
)
browse_btn.pack(side=tk.LEFT)

# Export button
export_btn = tk.Button(
    control_frame, 
    text="💾 Export Results", 
    command=export_results, 
    font=("Arial", 10), 
    bg="#28a745", 
    fg="white", 
    padx=15, 
    pady=10,
    cursor="hand2"
)
export_btn.pack(side=tk.LEFT, padx=(10, 0))

# Info label
info_label = tk.Label(
    control_frame, 
    text="Select an APK file to analyze its permissions and detect potential security issues",
    font=("Arial", 10),
    fg="gray"
)
info_label.pack(side=tk.LEFT, padx=(20, 0))

# Output text area
output_frame = tk.Frame(main_frame)
output_frame.pack(fill=tk.BOTH, expand=True)

output = scrolledtext.ScrolledText(
    output_frame, 
    wrap=tk.WORD, 
    font=("Consolas", 10),
    bg="#f8f9fa",
    fg="#333333",
    selectbackground="#007acc",
    selectforeground="white"
)
output.pack(fill=tk.BOTH, expand=True)

# Status bar
status_frame = tk.Frame(main_frame)
status_frame.pack(fill=tk.X, pady=(5, 0))

status_label = tk.Label(
    status_frame, 
    text="Ready - Select an APK file to begin analysis",
    font=("Arial", 9),
    fg="gray",
    anchor="w"
)
status_label.pack(fill=tk.X)

# Initial message
initial_msg = """
🔍 Android APK Permission Scanner v2.0

Welcome! This tool helps you analyze Android APK files for:
• Suspicious permissions that could indicate malware
• Unused permissions (over-privileged apps)
• Common RAT (Remote Access Trojan) indicators
• Certificate information and validity
• File integrity verification

✨ Features:
• Comprehensive permission analysis
• API usage detection
• RAT behavior indicators
• Export results to file
• Detailed error reporting

📋 Instructions:
1. Click "Browse APK File" to select an APK
2. Wait for the analysis to complete
3. Review the results
4. Export results if needed

⚙️ Requirements:
Make sure you have 'androguard' installed:
pip install androguard

🔒 Security Note:
Only analyze APK files from trusted sources. This tool is for educational 
and security research purposes.
"""

output.insert(tk.END, initial_msg)

# Start the GUI
if __name__ == "__main__":
    root.mainloop()