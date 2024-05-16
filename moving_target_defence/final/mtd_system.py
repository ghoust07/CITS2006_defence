# mtd_system.py
import threading
import time
import logging
import monitor
import yara_monitor
import timer
import RBAencryption
import RBAdecryption
import os

# Function to change protection settings
def change_protection_settings():
    # Log the start of protection settings change
    logging.info("Changing protection settings...")

    # Select a random cipher system and generate a new keyset
    new_cipher_system = RBAencryption.random.choice(['XOR', 'DES', 'VIG', 'RC4'])
    new_keyset = f'keyset{RBAencryption.random.randint(1, 100)}'

    # Log the new settings
    logging.info(f"New Cipher System: {new_cipher_system}")
    logging.info(f"New Keyset: {new_keyset}")

    # Encrypt files in the directory with the new settings
    directory = './ExampleDir/SubExampleDir'
    RBAencryption.main(new_cipher_system, new_keyset)

    # Log completion of protection settings change
    logging.info("Protection settings changed successfully.")

# Function to trigger MTD based on different events
def trigger_mtd(event_type):
    logging.info(f"Triggering MTD due to {event_type}")
    change_protection_settings()

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(filename='mtd_system.log', level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

    # Start file system monitoring
    monitor_thread = threading.Thread(target=monitor.start_monitoring, args=('./ExampleDir/SubExampleDir',))
    monitor_thread.daemon = True
    monitor_thread.start()

    # Start Yara monitoring
    rules = yara_monitor.load_yara_rules('./yara_rules')
    yara_thread = threading.Thread(target=yara_monitor.scan_file, args=(rules, './ExampleDir/SubExampleDir/test_malware.txt'))
    yara_thread.daemon = True
    yara_thread.start()

    # Start periodic MTD trigger
    interval = 10  # Trigger every 10 seconds for testing
    timer_thread = threading.Thread(target=timer.periodic_trigger, args=(interval,))
    timer_thread.daemon = True
    timer_thread.start()

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

