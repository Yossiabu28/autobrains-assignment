import hashlib
import os
import subprocess
import paramiko
import configparser
import gdown
from zipfile import ZipFile
from scp import SCPClient
import shutil


def delete_folder_if_needed(folder_path):
    if os.path.exists(folder_path) and os.path.isdir(folder_path):
        shutil.rmtree(folder_path)


def create_download_folder(download_folder):
    os.mkdir(download_folder)


def download_file_from_google_drive(file_id, download_folder, file_name):
    return gdown.download(id=file_id, output=f"{download_folder}\\{file_name}")


def extract_zip(zip_path, folder_path):
    with ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(path=folder_path)


def upload_folder(local_folder_path, remote_path, username, ip_address, private_key_path):
    # Create SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Load private key
    private_key = paramiko.RSAKey.from_private_key_file(private_key_path)

    try:
        # Connect to the server
        ssh.connect(hostname=ip_address, username=username, pkey=private_key)

        # SCPClient to transfer files
        with SCPClient(ssh.get_transport()) as scp:
            # Upload folder recursively
            scp.put(local_folder_path, recursive=True, remote_path=remote_path)

    except Exception as error:
        print(f"Error: {error}")
    finally:
        # Close the SSH connection
        ssh.close()


def get_local_folder_hash(folder_path):
    powershell_cmd = '(Get-ChildItem -Recurse -File ' + folder_path + ' | ForEach-Object { Get-FileHash $_.FullName -Algorithm MD5 }).Hash.ToLower()'
    result = subprocess.run(['powershell', '-Command', powershell_cmd], capture_output=True, text=True).stdout
    combined_hashes = ''.join(result.split())
    folder_hash = hashlib.md5(combined_hashes.encode()).hexdigest()
    return folder_hash


def get_remote_folder_hash(username, ip_address, private_key_path, remote_folder_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Load private key
    private_key = paramiko.RSAKey.from_private_key_file(private_key_path)

    try:
        ssh.connect(hostname=ip_address, username=username, pkey=private_key)
        # Execute command to calculate hash on remote VM
        stdin, stdout, stderr = ssh.exec_command(
            f"cd {remote_folder_path} && find . -type f -exec md5sum {{}} \\; | cut -d' ' -f1")
        result = stdout.read().decode()
        combined_hashes = ''.join(result.split())
        folder_hash = hashlib.md5(combined_hashes.encode()).hexdigest()
        return folder_hash
    except Exception as error:
        print(f"Error: {error}")
    finally:
        ssh.close()


config = configparser.ConfigParser()
config.read('.\\configuration.ini')

ip_vm = config['section_a']['ip_vm']
username_vm = config['section_a']['username_vm']
update_zip_google_drive_download_id = config['section_a']['update_zip_google_drive_download_id']
pem_file_google_drive_download_id = config['section_a']['pem_file_google_drive_download_id']
local_downloads_folder = config['section_a']['local_downloads_folder']
remote_path_to_upload_folder = config['section_a']['remote_path_to_upload_folder']

try:
    delete_folder_if_needed(local_downloads_folder)

    print("Downloading files from google drive")
    create_download_folder(local_downloads_folder)
    zip_file_path = download_file_from_google_drive(update_zip_google_drive_download_id, local_downloads_folder, "zip_file.zip")
    pem_file_path = download_file_from_google_drive(pem_file_google_drive_download_id, local_downloads_folder, "pem_file.pem")

    print("Extracting zip file")
    zip_content_path = f"{local_downloads_folder}\\zip_content"
    extract_zip(zip_file_path, zip_content_path)

    print("Uploading zip content to VM")
    upload_folder(zip_content_path, remote_path_to_upload_folder, username_vm, ip_vm, pem_file_path)

    remote_path = f"{remote_path_to_upload_folder}/zip_content"
    print("Checking if all copied files are valid")
    local_files_hash = get_local_folder_hash(zip_content_path)
    remote_files_hash = get_remote_folder_hash(username_vm, ip_vm, pem_file_path, remote_path)

    print(f"local files hash: {local_files_hash}")
    print(f"remote files hash: {remote_files_hash}")

    if local_files_hash == remote_files_hash:
        print("All the copied files are valid!")
    else:
        print("Something went wrong, please re-run the script")


except Exception as error:
    print(f"Error: {error}")


# local_hash = calculate_folder_hash(r"C:\Users\yossi\Desktop\Autobrains_New\Update\Update_zip\ros2_public_repo-main")
# print("***************************LOCAL*********")
# print(local_hash)
# print("***************************LOCAL*********")
#
#
# username = "ec2-user"
# ip_address = "54.87.124.176"
# private_key_path = r"C:\Users\yossi\Desktop\Yoss_key.pem"
# remote_folder_path = "/home/ec2-user/ros2_public_repo-main"
#
# remote_hash = get_remote_folder_hash(username, ip_address, private_key_path, remote_folder_path)
# print("***************************REMOTE*********")
# print(remote_hash)
# print("***************************REMOTE*********")
