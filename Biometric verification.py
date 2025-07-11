import hashlib
import hmac
import base64
import json
import cv2
import numpy as np
import pickle
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import face_recognition
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BiometricVerificationSystem:
    """Enhanced biometric verification system with encryption and security features"""
    
    def __init__(self, database_path: str = "biometric_db.pkl"):
        self.database_path = database_path
        self.biometric_database = self._load_database()
        self.encryption_key = self._generate_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.session_tokens = {}
        
    def _generate_encryption_key(self) -> bytes:
        """Generate encryption key for biometric data"""
        password = b"biometric_security_key_2024"
        salt = b"salt_for_biometric_system"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _load_database(self) -> Dict:
        """Load biometric database from file"""
        if os.path.exists(self.database_path):
            try:
                with open(self.database_path, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                logger.error(f"Error loading database: {e}")
                return {}
        return {}
    
    def _save_database(self):
        """Save biometric database to file"""
        try:
            with open(self.database_path, 'wb') as f:
                pickle.dump(self.biometric_database, f)
        except Exception as e:
            logger.error(f"Error saving database: {e}")
    
    def _encrypt_biometric_data(self, data: str) -> str:
        """Encrypt biometric data before storage"""
        return self.cipher_suite.encrypt(data.encode()).decode()
    
    def _decrypt_biometric_data(self, encrypted_data: str) -> str:
        """Decrypt biometric data for verification"""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
    
    def extract_face_encoding(self, image_path: str) -> Optional[np.ndarray]:
        """Extract face encoding from image with enhanced error handling"""
        try:
            # Load image
            image = face_recognition.load_image_file(image_path)
            
            # Find face locations
            face_locations = face_recognition.face_locations(image)
            
            if not face_locations:
                logger.warning("No face detected in image")
                return None
            
            # Extract face encodings
            face_encodings = face_recognition.face_encodings(image, face_locations)
            
            if not face_encodings:
                logger.warning("Could not extract face encoding")
                return None
            
            return face_encodings[0]
            
        except Exception as e:
            logger.error(f"Error extracting face encoding: {e}")
            return None
    
    def register_biometric(self, user_id: str, image_path: str, 
                          additional_data: Dict = None) -> bool:
        """Register biometric data for a user"""
        try:
            # Extract face encoding
            face_encoding = self.extract_face_encoding(image_path)
            
            if face_encoding is None:
                return False
            
            # Convert to serializable format
            encoding_data = {
                'encoding': face_encoding.tolist(),
                'timestamp': datetime.now().isoformat(),
                'additional_data': additional_data or {}
            }
            
            # Encrypt and store
            encrypted_data = self._encrypt_biometric_data(json.dumps(encoding_data))
            
            self.biometric_database[user_id] = {
                'encrypted_biometric': encrypted_data,
                'created_at': datetime.now().isoformat(),
                'last_verified': None,
                'verification_count': 0
            }
            
            self._save_database()
            logger.info(f"Biometric registered for user: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error registering biometric: {e}")
            return False
    
    def verify_biometric(self, user_id: str, image_path: str, 
                        tolerance: float = 0.6) -> Dict:
        """Verify biometric data with enhanced security"""
        try:
            # Check if user exists
            if user_id not in self.biometric_database:
                return {
                    'verified': False,
                    'error': 'User not found',
                    'confidence': 0.0
                }
            
            # Extract face encoding from provided image
            current_encoding = self.extract_face_encoding(image_path)
            
            if current_encoding is None:
                return {
                    'verified': False,
                    'error': 'Could not extract face from image',
                    'confidence': 0.0
                }
            
            # Decrypt stored biometric data
            user_data = self.biometric_database[user_id]
            decrypted_data = self._decrypt_biometric_data(user_data['encrypted_biometric'])
            stored_data = json.loads(decrypted_data)
            
            # Convert stored encoding back to numpy array
            stored_encoding = np.array(stored_data['encoding'])
            
            # Calculate face distance
            face_distances = face_recognition.face_distance([stored_encoding], current_encoding)
            face_distance = face_distances[0]
            
            # Determine if match
            is_match = face_distance <= tolerance
            confidence = max(0.0, 1.0 - face_distance)
            
            # Update verification statistics
            if is_match:
                self.biometric_database[user_id]['last_verified'] = datetime.now().isoformat()
                self.biometric_database[user_id]['verification_count'] += 1
                self._save_database()
                
                # Generate session token
                session_token = self._generate_session_token(user_id)
                
                return {
                    'verified': True,
                    'confidence': confidence,
                    'session_token': session_token,
                    'user_id': user_id,
                    'verification_time': datetime.now().isoformat()
                }
            else:
                return {
                    'verified': False,
                    'confidence': confidence,
                    'error': 'Biometric verification failed'
                }
                
        except Exception as e:
            logger.error(f"Error verifying biometric: {e}")
            return {
                'verified': False,
                'error': str(e),
                'confidence': 0.0
            }
    
    def _generate_session_token(self, user_id: str) -> str:
        """Generate secure session token"""
        timestamp = datetime.now().isoformat()
        token_data = f"{user_id}:{timestamp}:{os.urandom(16).hex()}"
        token = base64.urlsafe_b64encode(token_data.encode()).decode()
        
        # Store with expiration
        self.session_tokens[token] = {
            'user_id': user_id,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=24)
        }
        
        return token
    
    def verify_session_token(self, token: str) -> Optional[str]:
        """Verify session token and return user_id if valid"""
        if token in self.session_tokens:
            token_data = self.session_tokens[token]
            if datetime.now() < token_data['expires_at']:
                return token_data['user_id']
            else:
                # Remove expired token
                del self.session_tokens[token]
        return None
    
    def get_user_stats(self, user_id: str) -> Optional[Dict]:
        """Get user verification statistics"""
        if user_id in self.biometric_database:
            user_data = self.biometric_database[user_id].copy()
            # Remove sensitive data
            user_data.pop('encrypted_biometric', None)
            return user_data
        return None
    
    def live_face_verification(self, user_id: str, duration: int = 10) -> Dict:
        """Live face verification using webcam"""
        try:
            cap = cv2.VideoCapture(0)
            
            if not cap.isOpened():
                return {
                    'verified': False,
                    'error': 'Could not access camera'
                }
            
            start_time = datetime.now()
            successful_matches = 0
            total_attempts = 0
            
            while (datetime.now() - start_time).seconds < duration:
                ret, frame = cap.read()
                
                if not ret:
                    continue
                
                # Convert BGR to RGB
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                
                # Find faces
                face_locations = face_recognition.face_locations(rgb_frame)
                
                if face_locations:
                    face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
                    
                    if face_encodings:
                        total_attempts += 1
                        
                        # Get stored encoding
                        if user_id in self.biometric_database:
                            user_data = self.biometric_database[user_id]
                            decrypted_data = self._decrypt_biometric_data(user_data['encrypted_biometric'])
                            stored_data = json.loads(decrypted_data)
                            stored_encoding = np.array(stored_data['encoding'])
                            
                            # Check match
                            face_distances = face_recognition.face_distance([stored_encoding], face_encodings[0])
                            
                            if face_distances[0] <= 0.6:
                                successful_matches += 1
                
                # Display frame
                cv2.imshow('Live Verification', frame)
                
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
            
            cap.release()
            cv2.destroyAllWindows()
            
            # Calculate success rate
            if total_attempts > 0:
                success_rate = successful_matches / total_attempts
                verified = success_rate >= 0.7  # 70% success rate threshold
                
                return {
                    'verified': verified,
                    'success_rate': success_rate,
                    'total_attempts': total_attempts,
                    'successful_matches': successful_matches
                }
            else:
                return {
                    'verified': False,
                    'error': 'No face detected during verification'
                }
                
        except Exception as e:
            logger.error(f"Error in live verification: {e}")
            return {
                'verified': False,
                'error': str(e)
            }

# API Interface for integration with other components
class BiometricAPI:
    """API interface for biometric verification system"""
    
    def __init__(self):
        self.biometric_system = BiometricVerificationSystem()
    
    def register_user(self, user_id: str, image_path: str, metadata: Dict = None) -> Dict:
        """Register a new user"""
        success = self.biometric_system.register_biometric(user_id, image_path, metadata)
        return {
            'success': success,
            'user_id': user_id,
            'message': 'User registered successfully' if success else 'Registration failed'
        }
    
    def authenticate_user(self, user_id: str, image_path: str) -> Dict:
        """Authenticate user with biometric"""
        return self.biometric_system.verify_biometric(user_id, image_path)
    
    def validate_session(self, token: str) -> Dict:
        """Validate session token"""
        user_id = self.biometric_system.verify_session_token(token)
        return {
            'valid': user_id is not None,
            'user_id': user_id
        }
    
    def get_user_info(self, user_id: str) -> Dict:
        """Get user information"""
        stats = self.biometric_system.get_user_stats(user_id)
        return {
            'found': stats is not None,
            'data': stats
        }

# Example usage
if __name__ == "__main__":
    # Initialise system
    bio_api = BiometricAPI()
    
    # Example registration
    # result = bio_api.register_user("user_001", "path/to/image.jpg", {"name": "John Doe"})
    # print(f"Registration: {result}")
    
    # Example authentication
    # auth_result = bio_api.authenticate_user("user_001", "path/to/verification_image.jpg")
    # print(f"Authentication: {auth_result}")
    
    print("Enhanced Biometric Verification System initialized successfully!")
    print("Key features:")
    print("- Encrypted biometric data storage")
    print("- Session token management")
    print("- Live face verification")
    print("- Comprehensive error handling")
    print("- API interface for integration")
