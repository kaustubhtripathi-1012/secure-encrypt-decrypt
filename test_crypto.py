import sys
from crypto_helper import encrypt_message, decrypt_message

def run_tests():
    print("Starting Cryptographic Logic Validation...")
    
    test_msg = "Confidential Message: The eagle flies at midnight."
    password = "SuperSafePassword123"
    secret_key = "ABCDEF123456"
    
    # 1. Test Encryption
    print("- Testing encryption...")
    enc_data = encrypt_message(test_msg, password, secret_key)
    
    assert 'ciphertext' in enc_data, "Ciphertext missing"
    assert 'nonce' in enc_data, "Nonce missing"
    assert 'tag' in enc_data, "Tag missing"
    assert 'salt' in enc_data, "Salt missing"
    print("  [OK] Encryption output is correctly structured.")
    
    # 2. Test Decryption with correct credentials
    print("- Testing decryption with correct credentials...")
    decrypted = decrypt_message(
        enc_data['ciphertext'],
        enc_data['nonce'],
        enc_data['tag'],
        enc_data['salt'],
        password,
        secret_key
    )
    
    assert decrypted == test_msg, f"Decryption failed: expected '{test_msg}', got '{decrypted}'"
    print("  [OK] Decrypted message matches original plaintext.")
    
    # 3. Test Decryption with incorrect password
    print("- Testing decryption failure with incorrect password...")
    bad_decrypted = decrypt_message(
        enc_data['ciphertext'],
        enc_data['nonce'],
        enc_data['tag'],
        enc_data['salt'],
        "WrongPassword",
        secret_key
    )
    assert bad_decrypted is None, "Decryption should have failed for wrong password"
    print("  [OK] Decryption correctly returned None (failed authentication check).")
    
    # 4. Test Decryption with incorrect secret key
    print("- Testing decryption failure with incorrect secret key...")
    bad_decrypted_key = decrypt_message(
        enc_data['ciphertext'],
        enc_data['nonce'],
        enc_data['tag'],
        enc_data['salt'],
        password,
        "WrongSecretKey"
    )
    assert bad_decrypted_key is None, "Decryption should have failed for wrong secret key"
    print("  [OK] Decryption correctly returned None (failed authentication check).")
    
    # 5. Test Decryption with combined ciphertext
    print("- Testing decryption with combined ciphertext (implicit salt/nonce)...")
    decrypted_combined = decrypt_message(
        enc_data['combined_ciphertext'],
        None,
        enc_data['tag'],
        None,
        password,
        secret_key
    )
    assert decrypted_combined == test_msg, f"Combined decryption failed: expected '{test_msg}', got '{decrypted_combined}'"
    print("  [OK] Combined decryption matched original plaintext successfully.")
    
    print("\n[SUCCESS] All Cryptographic Validation Tests Passed!")

if __name__ == "__main__":
    run_tests()
