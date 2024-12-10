import subprocess
class LicenseVerifier:
    def __init__(self):
        self.valid_license_key = "CB5@Project"
        self.remaining_attempts = 3

    def verify_license_key(self, key):
        if key == self.valid_license_key:
            return True
        else:
            self.remaining_attempts -= 1
            return False

    def run(self):
        print("Welcome to License Key Verification!")
        while self.remaining_attempts > 0:
            key = input(f"Enter the license key ({self.remaining_attempts} attempts remaining): ")
            if self.verify_license_key(key):
                print("License key is valid. Launching application...")
                return True
            else:
                if self.remaining_attempts > 0:
                    print("Invalid license key. Please try again.")
                else:
                    print("Invalid license key. Exiting...")
                    return False

if __name__ == "__main__":
    verifier = LicenseVerifier()
    if verifier.run():
        # Run the final application here
        subprocess.run(["python3", "final.py"])