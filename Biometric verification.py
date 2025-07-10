"""
Advanced Biometric Verification System for ADIS
Implements multi-modal biometric authentication with AI-powered verification
"""

import numpy as np
import cv2
import hashlib
import base64
from typing import Dict, List, Tuple, Optional
import tensorflow as tf
from sklearn.ensemble import IsolationForest
from scipy.spatial.distance import cosine
import librosa
import pickle
import logging
from datetime import datetime
import asyncio
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class BiometricVerificationSystem:
    """Advanced multi-modal biometric verification system"""
    
    def __init__(self, model_path: str = "models/"):
        self.model_path = model_path
        self.face_detector = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        self.face_recognizer = cv2.face.LBPHFaceRecognizer_create()
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.logger = self._setup_logging()
        
        # Load pre-trained models
        self._load_models()
        
        # Initialize verification thresholds
        self.verification_thresholds = {
            'facial': 0.85,
            'fingerprint': 0.90,
            'voice': 0.80,
            'iris': 0.95,
            'behavioral': 0.75,
            'dna': 0.99
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the verification system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(__name__)
    
    def _load_models(self):
        """Load pre-trained AI models for biometric verification"""
        try:
            # Load facial recognition model
            self.face_model = tf.keras.models.load_model(
                f"{self.model_path}face_recognition_model.h5",
                compile=False
            ) if os.path.exists(f"{self.model_path}face_recognition_model.h5") else None
            
            # Load voice recognition model
            self.voice_model = tf.keras.models.load_model(
                f"{self.model_path}voice_recognition_model.h5",
                compile=False
            ) if os.path.exists(f"{self.model_path}voice_recognition_model.h5") else None
            
            # Load behavioral pattern model
            self.behavioral_model = tf.keras.models.load_model(
                f"{self.model_path}behavioral_model.h5",
                compile=False
            ) if os.path.exists(f"{self.model_path}behavioral_model.h5") else None
            
            self.logger.info("Models loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            self._create_default_models()
    
    def _create_default_models(self):
        """Create default models if pre-trained ones are not available"""
        # Create simple CNN for face recognition
        self.face_model = tf.keras.Sequential([
            tf.keras.layers.Conv2D(32, (3, 3), activation='relu', input_shape=(128, 128, 3)),
            tf.keras.layers.MaxPooling2D((2, 2)),
            tf.keras.layers.Conv2D(64, (3, 3), activation='relu'),
            tf.keras.layers.MaxPooling2D((2, 2)),
            tf.keras.layers.Conv2D(64, (3, 3), activation='relu'),
            tf.keras.layers.Flatten(),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(128, activation='sigmoid')  # Feature vector
        ])
        
        # Create voice recognition model
        self.voice_model = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu', input_shape=(40,)),  # MFCC features
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(128, activation='sigmoid')  # Voice print
        ])
        
        # Create behavioral model
        self.behavioral_model = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu', input_shape=(50,)),  # Behavioral features
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(16, activation='relu'),
            tf.keras.layers.Dense(32, activation='sigmoid')  # Behavioral signature
        ])
    
    def extract_facial_features(self, image_data: np.ndarray) -> Tuple[np.ndarray, float]:
        """Extract facial features with liveness detection"""
        try:
            # Convert to grayscale for face detection
            gray = cv2.cvtColor(image_data, cv2.COLOR_BGR2GRAY)
            
            # Detect faces
            faces = self.face_detector.detectMultiScale(gray, 1.3, 5)
            
            if len(faces) == 0:
                return None, 0.0
            
            # Get the largest face
            face = max(faces, key=lambda x: x[2] * x[3])
            x, y, w, h = face
            
            # Extract face region
            face_roi = image_data[y:y+h, x:x+w]
            face_roi = cv2.resize(face_roi, (128, 128))
            
            # Liveness detection
            liveness_score = self._detect_liveness(face_roi)
            
            if liveness_score < 0.5:
                self.logger.warning("Failed liveness detection")
                return None, liveness_score
            
            # Extract features using the model
            if self.face_model:
                face_input = np.expand_dims(face_roi / 255.0, axis=0)
                features = self.face_model.predict(face_input, verbose=0)[0]
            else:
                # Fallback to basic features
                features = self._extract_basic_face_features(face_roi)
            
            return features, liveness_score
            
        except Exception as e:
            self.logger.error(f"Error extracting facial features: {e}")
            return None, 0.0
    
    def _detect_liveness(self, face_roi: np.ndarray) -> float:
        """Detect if the face is from a live person"""
        try:
            # Simple liveness detection based on texture analysis
            gray = cv2.cvtColor(face_roi, cv2.COLOR_BGR2GRAY)
            
            # Calculate texture features
            sobel_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
            sobel_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
            
            # Calculate gradient magnitude
            gradient_magnitude = np.sqrt(sobel_x**2 + sobel_y**2)
            
            # Analyze texture complexity
            texture_score = np.std(gradient_magnitude) / np.mean(gradient_magnitude)
            
            # Normalize score (higher complexity = more likely to be live)
            liveness_score = min(1.0, texture_score / 50.0)
            
            return liveness_score
            
        except Exception as e:
            self.logger.error(f"Error in liveness detection: {e}")
            return 0.0
    
    def _extract_basic_face_features(self, face_roi: np.ndarray) -> np.ndarray:
        """Extract basic facial features as fallback"""
        # Convert to grayscale
        gray = cv2.cvtColor(face_roi, cv2.COLOR_BGR2GRAY)
        
        # Calculate histogram
        hist = cv2.calcHist([gray], [0], None, [256], [0, 256])
        hist = hist.flatten()
        
        # Normalize and resize to 128 dimensions
        hist = hist / np.sum(hist)
        features = np.resize(hist, 128)
        
        return features
    
    def extract_fingerprint_features(self, fingerprint_data: np.ndarray) -> np.ndarray:
        """Extract fingerprint minutiae features"""
        try:
            # Convert to grayscale if needed
            if len(fingerprint_data.shape) == 3:
                gray = cv2.cvtColor(fingerprint_data, cv2.COLOR_BGR2GRAY)
            else:
                gray = fingerprint_data
            
            # Enhance fingerprint image
            enhanced = self._enhance_fingerprint(gray)
            
            # Extract minutiae points
            minutiae = self._extract_minutiae(enhanced)
            
            # Create feature vector from minutiae
            features = self._minutiae_to_features(minutiae)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting fingerprint features: {e}")
            return np.zeros(128)
    
    def _enhance_fingerprint(self, fingerprint: np.ndarray) -> np.ndarray:
        """Enhance fingerprint image quality"""
        # Apply histogram equalization
        enhanced = cv2.equalizeHist(fingerprint)
        
        # Apply Gaussian blur to reduce noise
        enhanced = cv2.GaussianBlur(enhanced, (3, 3), 0)
        
        # Apply sharpening filter
        kernel = np.array([[-1,-1,-1], [-1,9,-1], [-1,-1,-1]])
        enhanced = cv2.filter2D(enhanced, -1, kernel)
        
        return enhanced
    
    def _extract_minutiae(self, enhanced_fp: np.ndarray) -> List[Tuple[int, int, float]]:
        """Extract minutiae points from enhanced fingerprint"""
        # Simple minutiae extraction using corner detection
        corners = cv2.goodFeaturesToTrack(
            enhanced_fp,
            maxCorners=100,
            qualityLevel=0.01,
            minDistance=10,
            useHarrisDetector=True
        )
        
        minutiae = []
        if corners is not None:
            for corner in corners:
                x, y = corner.ravel()
                # Calculate orientation at this point
                orientation = self._calculate_orientation(enhanced_fp, int(x), int(y))
                minutiae.append((int(x), int(y), orientation))
        
        return minutiae
    
    def _calculate_orientation(self, image: np.ndarray, x: int, y: int) -> float:
        """Calculate orientation at a specific point"""
        try:
            # Get local region
            region_size = 16
            x1, y1 = max(0, x - region_size//2), max(0, y - region_size//2)
            x2, y2 = min(image.shape[1], x + region_size//2), min(image.shape[0], y + region_size//2)
            
            region = image[y1:y2, x1:x2]
            
            # Calculate gradient
            sobel_x = cv2.Sobel(region, cv2.CV_64F, 1, 0, ksize=3)
            sobel_y = cv2.Sobel(region, cv2.CV_64F, 0, 1, ksize=3)
            
            # Calculate orientation
            orientation = np.arctan2(np.mean(sobel_y), np.mean(sobel_x))
            
            return orientation
            
        except Exception as e:
            return 0.0
    
    def _minutiae_to_features(self, minutiae: List[Tuple[int, int, float]]) -> np.ndarray:
        """Convert minutiae points to feature vector"""
        features = np.zeros(128)
        
        if not minutiae:
            return features
        
        # Convert minutiae to relative coordinates and orientations
        for i, (x, y, orientation) in enumerate(minutiae[:42]):  # Limit to 42 points
            base_idx = i * 3
            if base_idx + 2 < len(features):
                features[base_idx] = x / 512.0  # Normalize coordinates
                features[base_idx + 1] = y / 512.0
                features[base_idx + 2] = orientation / (2 * np.pi)  # Normalize orientation
        
        return features
    
    def extract_voice_features(self, audio_data: np.ndarray, sample_rate: int = 16000) -> np.ndarray:
        """Extract voice features from audio data"""
        try:
            # Extract MFCC features
            mfcc = librosa.feature.mfcc(y=audio_data, sr=sample_rate, n_mfcc=40)
            mfcc_mean = np.mean(mfcc, axis=1)
            
            # Extract additional features
            spectral_centroid = librosa.feature.spectral_centroid(y=audio_data, sr=sample_rate)
            spectral_rolloff = librosa.feature.spectral_rolloff(y=audio_data, sr=sample_rate)
            zero_crossing_rate = librosa.feature.zero_crossing_rate(audio_data)
            
            # Combine features
            voice_features = np.concatenate([
                mfcc_mean,
                [np.mean(spectral_centroid)],
                [np.mean(spectral_rolloff)],
                [np.mean(zero_crossing_rate)]
            ])
            
            # Use voice model if available
            if self.voice_model and len(voice_features) >= 40:
                voice_input = np.expand_dims(voice_features[:40], axis=0)
                voice_print = self.voice_model.predict(voice_input, verbose=0)[0]
                return voice_print
            
            # Pad or truncate to 128 dimensions
            if len(voice_features) < 128:
                voice_features = np.pad(voice_features, (0, 128 - len(voice_features)))
            else:
                voice_features = voice_features[:128]
            
            return voice_features
            
        except Exception as e:
            self.logger.error(f"Error extracting voice features: {e}")
            return np.zeros(128)
    
    def extract_iris_features(self, iris_data: np.ndarray) -> np.ndarray:
        """Extract iris features using advanced pattern recognition"""
        try:
            # Convert to grayscale
            if len(iris_data.shape) == 3:
                gray = cv2.cvtColor(iris_data, cv2.COLOR_BGR2GRAY)
            else:
                gray = iris_data
            
            # Detect iris region
            iris_region = self._detect_iris_region(gray)
            
            if iris_region is None:
                return np.zeros(128)
            
            # Normalize iris region
            normalized_iris = self._normalize_iris(iris_region)
            
            # Extract Gabor features
            gabor_features = self._extract_gabor_features(normalized_iris)
            
            return gabor_features
            
        except Exception as e:
            self.logger.error(f"Error extracting iris features: {e}")
            return np.zeros(128)
    
    def _detect_iris_region(self, eye_image: np.ndarray) -> Optional[np.ndarray]:
        """Detect iris region in eye image"""
        try:
            # Use Hough Circle Transform to detect iris
            circles = cv2.HoughCircles(
                eye_image,
                cv2.HOUGH_GRADIENT,
                dp=1,
                minDist=30,
                param1=50,
                param2=30,
                minRadius=20,
                maxRadius=80
            )
            
            if circles is not None:
                circles = np.round(circles[0, :]).astype("int")
                # Get the largest circle (iris)
                largest_circle = max(circles, key=lambda x: x[2])
                x, y, r = largest_circle
                
                # Extract iris region
                iris_region = eye_image[y-r:y+r, x-r:x+r]
                return iris_region
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error detecting iris region: {e}")
            return None
    
    def _normalize_iris(self, iris_region: np.ndarray) -> np.ndarray:
        """Normalize iris region to standard size"""
        try:
            # Resize to standard size
            normalized = cv2.resize(iris_region, (64, 64))
            
            # Apply histogram equalization
            normalized = cv2.equalizeHist(normalized)
            
            return normalized
            
        except Exception as e:
            self.logger.error(f"Error normalizing iris: {e}")
            return iris_region
    
    def _extract_gabor_features(self, normalized_iris: np.ndarray) -> np.ndarray:
        """Extract Gabor filter features from normalized iris"""
        try:
            features = []
            
            # Apply Gabor filters with different orientations and frequencies
            for theta in [0, 45, 90, 135]:  # Different orientations
                for frequency in [0.1, 0.3, 0.5]:  # Different frequencies
                    # Create Gabor kernel
                    kernel = cv2.getGaborKernel(
                        (21, 21),
                        sigma=3,
                        theta=np.radians(theta),
                        lambd=1.0/frequency,
                        gamma=0.5,
                        psi=0
                    )
                    
                    # Apply filter
                    filtered = cv2.filter2D(normalized_iris, cv2.CV_8UC3, kernel)
                    
                    # Extract statistical features
                    features.extend([
                        np.mean(filtered),
                        np.std(filtered),
                        np.max(filtered),
                        np.min(filtered)
                    ])
            
            # Convert to numpy array and normalize
            features = np.array(features)
            features = features / np.linalg.norm(features) if np.linalg.norm(features) > 0 else features
            
            # Pad or truncate to 128 dimensions
            if len(features) < 128:
                features = np.pad(features, (0, 128 - len(features)))
            else:
                features = features[:128]
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting Gabor features: {e}")
            return np.zeros(128)
    
    def extract_behavioral_features(self, behavioral_data: Dict) -> np.ndarray:
        """Extract behavioral biometric features"""
        try:
            features = []
            
            # Keystroke dynamics
            if 'keystrokes' in behavioral_data:
                keystroke_features = self._extract_keystroke_features(behavioral_data['keystrokes'])
                features.extend(keystroke_features)
            
            # Mouse movement patterns
            if 'mouse_movements' in behavioral_data:
                mouse_features = self._extract_mouse_features(behavioral_data['mouse_movements'])
                features.extend(mouse_features)
            
            # Gait analysis
            if 'gait_data' in behavioral_data:
                gait_features = self._extract_gait_features(behavioral_data['gait_data'])
                features.extend(gait_features)
            
            # Convert to numpy array
            features = np.array(features)
            
            # Use behavioral model if available
            if self.behavioral_model and len(features) >= 50:
                behavioral_input = np.expand_dims(features[:50], axis=0)
                behavioral_signature = self.behavioral_model.predict(behavioral_input, verbose=0)[0]
                return behavioral_signature
            
            # Pad or truncate to 128 dimensions
            if len(features) < 128:
                features = np.pad(features, (0, 128 - len(features)))
            else:
                features = features[:128]
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting behavioral features: {e}")
            return np.zeros(128)
    
    def _extract_keystroke_features(self, keystrokes: List[Dict]) -> List[float]:
        """Extract keystroke dynamics features"""
        features = []
        
        if not keystrokes:
            return [0.0] * 20
        
        # Calculate timing features
        dwell_times = [ks.get('dwell_time', 0) for ks in keystrokes]
        flight_times = [ks.get('flight_time', 0) for ks in keystrokes]
        
        # Statistical features
        features.extend([
            np.mean(dwell_times),
            np.std(dwell_times),
            np.max(dwell_times),
            np.min(dwell_times),
            np.mean(flight_times),
            np.std(flight_times),
            np.max(flight_times),
            np.min(flight_times)
        ])
        
        # Rhythm features
        if len(dwell_times) > 1:
            rhythm_variance = np.var(dwell_times)
            features.append(rhythm_variance)
        else:
            features.append(0.0)
        
        # Pad to 20 features
        while len(features) < 20:
            features.append(0.0)
        
        return features[:20]
    
    def _extract_mouse_features(self, mouse_movements: List[Dict]) -> List[float]:
        """Extract mouse movement pattern features"""
        features = []
        
        if not mouse_movements:
            return [0.0] * 15
        
        # Calculate movement statistics
        velocities = [mm.get('velocity', 0) for mm in mouse_movements]
        accelerations = [mm.get('acceleration', 0) for mm in mouse_movements]
        angles = [mm.get('angle', 0) for mm in mouse_movements]
        
        # Velocity features
        features.extend([
            np.mean(velocities),
            np.std(velocities),
            np.max(velocities),
            np.min(velocities)
        ])
        
        # Acceleration features
        features.extend([
            np.mean(accelerations),
            np.std(accelerations),
            np.max(accelerations),
            np.min(accelerations)
        ])
        
        # Angle features
        features.extend([
            np.mean(angles),
            np.std(angles),
            np.max(angles),
            np.min(angles)
        ])
        
        # Movement smoothness
        if len(velocities) > 1:
            smoothness = np.var(velocities)
            features.append(smoothness)
        else:
            features.append(0.0)
        
        # Pad to 15 features
        while len(features) < 15:
            features.append(0.0)
        
        return features[:15]
    
    def _extract_gait_features(self, gait_data: Dict) -> List[float]:
        """Extract gait analysis features"""
        features = []
        
        # Step frequency
        features.append(gait_data.get('step_frequency', 0.0))
        
        # Stride length
        features.append(gait_data.get('stride_length', 0.0))
        
        # Step variability
        features.append(gait_data.get('step_variability', 0.0))
        
        # Gait symmetry
        features.append(gait_data.get('gait_symmetry', 0.0))
        
        # Walking speed
        features.append(gait_data.get('walking_speed', 0.0))
        
        # Pad to 15 features
        while len(features) < 15:
            features.append(0.0)
        
        return features[:15]
    
    def extract_dna_features(self, dna_sequence: str) -> np.ndarray:
        """Extract DNA sequence features for genetic verification"""
        try:
            # Convert DNA sequence to numerical representation
            dna_mapping = {'A': 0, 'T': 1, 'G': 2, 'C': 3}
            
            # Extract k-mer features
            k = 3  # Use 3-mers
            kmers = {}
            
            for i in range(len(dna_sequence) - k + 1):
                kmer = dna_sequence[i:i+k]
                if all(base in dna_mapping for base in kmer):
                    kmers[kmer] = kmers.get(kmer, 0) + 1
            
            # Create feature vector from k-mer frequencies
            features = []
            all_possible_kmers = [''.join(combo) for combo in 
                                [''.join(p) for p in __import__('itertools').product('ATGC', repeat=k)]]
            
            for kmer in all_possible_kmers:
                features.append(kmers.get(kmer, 0))
            
            # Normalize features
            features = np.array(features, dtype=float)
            if np.sum(features) > 0:
                features = features / np.sum(features)
            
            # Pad or truncate to 128 dimensions
            if len(features) < 128:
                features = np.pad(features, (0, 128 - len(features)))
            else:
                features = features[:128]
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting DNA features: {e}")
            return np.zeros(128)
    
    def create_biometric_template(self, biometric_data: Dict) -> Dict[str, bytes]:
        """Create encrypted biometric template"""
        try:
            template = {}
            
            # Extract features for each biometric modality
            if 'facial_image' in biometric_data:
                facial_features, liveness_score = self.extract_facial_features(biometric_data['facial_image'])
                if facial_features is not None and liveness_score > 0.5:
                    template['facial'] = self._encrypt_features(facial_features)
            
            if 'fingerprint_image' in biometric_data:
                fingerprint_features = self.extract_fingerprint_features(biometric_data['fingerprint_image'])
                template['fingerprint'] = self._encrypt_features(fingerprint_features)
            
            if 'voice_audio' in biometric_data:
                voice_features = self.extract_voice_features(biometric_data['voice_audio'])
                template['voice'] = self._encrypt_features(voice_features)
            
            if 'iris_image' in biometric_data:
                iris_features = self.extract_iris_features(biometric_data['iris_image'])
                template['iris'] = self._encrypt_features(iris_features)
            
            if 'behavioral_data' in biometric_data:
                behavioral_features = self.extract_behavioral_features(biometric_data['behavioral_data'])
                template['behavioral'] = self._encrypt_features(behavioral_features)
            
            if 'dna_sequence' in biometric_data:
                dna_features = self.extract_dna_features(biometric_data['dna_sequence'])
                template['dna'] = self._encrypt_features(dna_features)
            
            return template
            
        except Exception as e:
            self.logger.error(f"Error creating biometric template: {e}")
            return {}
    
    def _encrypt_features(self, features: np.ndarray) -> bytes:
        """Encrypt biometric features for secure storage"""
        try:
            # Generate salt and key
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(b"biometric_key")  # In production, use proper key management
            
            # Encrypt features
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Serialize and pad features
            features_bytes = features.tobytes()
            padding_length = 16 - (len(features_bytes) % 16)
            padded_features = features_bytes + bytes([padding_length] * padding_length)
            
            encrypted_features = encryptor.update(padded_features) + encryptor.finalize()
            
            # Combine salt, iv, and encrypted data
            return salt + iv + encrypted_features
            
        except Exception as e:
            self.logger.error(f"Error encrypting features: {e}")
            return b""
    
    def _decrypt_features(self, encrypted_data: bytes) -> np.ndarray:
        """Decrypt biometric features for comparison"""
        try:
            # Extract salt, iv, and encrypted data
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            encrypted_features = encrypted_data[32:]
            
            # Derive key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(b"biometric_key")
            
            # Decrypt features
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            padded_features = decryptor.update(encrypted_features) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_features[-1]
            features_bytes = padded_features[:-padding_length]
            
            # Convert back to numpy array
            features = np.frombuffer(features_bytes, dtype=np.float64)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error decrypting features: {e}")
            return np.zeros(128)
    
    def verify_biometric_template(self, stored_template: Dict[str, bytes], 
                                 verification_data: Dict) -> Dict[str, float]:
        """Verify biometric data against stored template"""
        try:
            verification_scores = {}
            
            # Verify each biometric modality
            for modality in stored_template:
                if modality == 'facial' and 'facial_image' in verification_data:
                    score = self._verify_facial(stored_template[modality], verification_data['facial_image'])
                    verification_scores[modality] = score
                
                elif modality == 'fingerprint' and 'fingerprint_image' in verification_data:
                    score = self._verify_fingerprint(stored_template[modality], verification_data['fingerprint_image'])
                    verification_scores[modality] = score
                
                elif modality == 'voice' and 'voice_audio' in verification_data:
                    score = self._verify_voice(stored_template[modality], verification_data['voice_audio'])
                    verification_scores[modality] = score
                
                elif modality == 'iris' and 'iris_image' in verification_data:
                    score = self._verify_iris(stored_template[modality], verification_data['iris_image'])
                    verification_scores[modality] = score
                
                elif modality == 'behavioral' and 'behavioral_data' in verification_data:
                    score = self._verify_behavioral(stored_template[modality], verification_data['behavioral_data'])
                    verification_scores[modality] = score
                
                elif modality == 'dna' and 'dna_sequence' in verification_data:
                    score = self._verify_dna(stored_template[modality], verification_data['dna_sequence'])
                    verification_scores[modality] = score
            
            return verification_scores
            
        except Exception as e:
            self.logger.error(f"Error verifying biometric template: {e}")
            return {}
    
    def _verify_facial(self, stored_features: bytes, facial_image: np.ndarray) -> float:
        """Verify facial biometric"""
        try:
            # Decrypt stored features
            stored = self._decrypt_features(stored_features)
            
            # Extract features from new image
            new_features, liveness_score = self.extract_facial_features(facial_image)
            
            if new_features is None or liveness_score < 0.5:
                return 0.0
            
            # Calculate similarity
            similarity = 1 - cosine(stored, new_features)
            
            # Combine with liveness score
            final_score = similarity * liveness_score
            
            return max(0.0, min(1.0, final_score))
            
        except Exception as e:
            self.logger.error(f"Error verifying facial biometric: {e}")
            return 0.0
    
    def _verify_fingerprint(self, stored_features: bytes, fingerprint_image: np.ndarray) -> float:
        """Verify fingerprint biometric"""
        try:
            stored = self._decrypt_features(stored_features)
            new_features = self.extract_fingerprint_features(fingerprint_image)
            
            similarity = 1 - cosine(stored, new_features)
            return max(0.0, min(1.0, similarity))
            
        except Exception as e:
            self.logger.error(f"Error verifying fingerprint biometric: {e}")
            return 0.0
    
    def _verify_voice(self, stored_features: bytes, voice_audio: np.ndarray) -> float:
        """Verify voice biometric"""
        try:
            stored = self._decrypt_features(stored_features)
            new_features = self.extract_voice_features(voice_audio)
            
            similarity = 1 - cosine(stored, new_features)
            return max(0.0, min(1.0, similarity))
            
        except Exception as e:
            self.logger.error(f"Error verifying voice biometric: {e}")
            return 0.0
    
    def _verify_iris(self, stored_features: bytes, iris_image: np.ndarray) -> float:
        """Verify iris biometric"""
        try:
            stored = self._decrypt_features(stored_features)
            new_features = self.extract_iris_features(iris_image)
            
            similarity = 1 - cosine(stored, new_features)
            return max(0.0, min(1.0, similarity))
            
        except Exception as e:
            self.logger.error(f"Error verifying iris biometric: {e}")
            return 0.0
    
    def _verify_behavioral(self, stored_features: bytes, behavioral_data: Dict) -> float:
        """Verify behavioral biometric"""
        try:
            stored = self._decrypt_features(stored_features)
            new_features = self.extract_behavioral_features(behavioral_data)
            
            similarity = 1 - cosine(stored, new_features)
            return max(0.0, min(1.0, similarity))
            
        except Exception as e:
            self.logger.error(f"Error verifying behavioral biometric: {e}")
            return 0.0
    
    def _verify_dna(self, stored_features: bytes, dna_sequence: str) -> float:
        """Verify DNA biometric"""
        try:
            stored = self._decrypt_features(stored_features)
            new_features = self.extract_dna_features(dna_sequence)
            
            similarity = 1 - cosine(stored, new_features)
            return max(0.0, min(1.0, similarity))
            
        except Exception as e:
            self.logger.error(f"Error verifying DNA biometric: {e}")
            return 0.0
    
    def calculate_fusion_score(self, verification_scores: Dict[str, float]) -> float:
        """Calculate final fusion score from all biometric modalities"""
        try:
            if not verification_scores:
                return 0.0
            
            # Weight different biometric modalities
            weights = {
                'facial': 0.2,
                'fingerprint': 0.25,
                'voice': 0.15,
                'iris': 0.25,
                'behavioral': 0.1,
                'dna': 0.05
            }
            
            weighted_score = 0.0
            total_weight = 0.0
            
            for modality, score in verification_scores.items():
                if modality in weights:
                    weighted_score += score * weights[modality]
                    total_weight += weights[modality]
            
            if total_weight > 0:
                final_score = weighted_score / total_weight
            else:
                final_score = 0.0
            
            return final_score
            
        except Exception as e:
            self.logger.error(f"Error calculating fusion score: {e}")
            return 0.0
    
    def create_biometric_hash(self, template: Dict[str, bytes]) -> str:
        """Create a unique hash for the biometric template"""
        try:
            # Combine all encrypted features
            combined_data = b""
            for modality in sorted(template.keys()):
                combined_data += template[modality]
            
            # Create hash
            hash_obj = hashlib.sha256()
            hash_obj.update(combined_data)
            
            return hash_obj.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Error creating biometric hash: {e}")
            return ""


class BiometricAntiSpoofing:
    """Advanced anti-spoofing mechanisms for biometric verification"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def detect_facial_spoofing(self, image: np.ndarray) -> Dict[str, float]:
        """Detect facial spoofing attempts"""
        try:
            results = {}
            
            # Texture analysis
            results['texture_score'] = self._analyze_texture(image)
            
            # Color analysis
            results['color_score'] = self._analyze_color_distribution(image)
            
            # 3D analysis
            results['depth_score'] = self._analyze_depth_cues(image)
            
            # Motion analysis (requires video frames)
            results['motion_score'] = 0.5  # Placeholder
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error detecting facial spoofing: {e}")
            return {'texture_score': 0.0, 'color_score': 0.0, 'depth_score': 0.0, 'motion_score': 0.0}
    
    def _analyze_texture(self, image: np.ndarray) -> float:
        """Analyze texture patterns for spoofing detection"""
        try:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Calculate Local Binary Pattern
            lbp = cv2.calcHist([gray], [0], None, [256], [0, 256])
            
            # Calculate texture complexity
            texture_complexity = np.std(lbp) / np.mean(lbp) if np.mean(lbp) > 0 else 0
            
            # Normalize score
            texture_score = min(1.0, texture_complexity / 10.0)
            
            return texture_score
            
        except Exception as e:
            self.logger.error(f"Error analyzing texture: {e}")
            return 0.0
    
    def _analyze_color_distribution(self, image: np.ndarray) -> float:
        """Analyze color distribution for spoofing detection"""
        try:
            # Convert to different color spaces
            hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
            lab = cv2.cvtColor(image, cv2.COLOR_BGR2LAB)
            
            # Analyze color distribution
            h_hist = cv2.calcHist([hsv], [0], None, [180], [0, 180])
            s_hist = cv2.calcHist([hsv], [1], None, [256], [0, 256])
            
            # Calculate color diversity
            h_diversity = np.count_nonzero(h_hist) / len(h_hist)
            s_diversity = np.count_nonzero(s_hist) / len(s_hist)
            
            color_score = (h_diversity + s_diversity) / 2
            
            return color_score
            
        except Exception as e:
            self.logger.error(f"Error analyzing color distribution: {e}")
            return 0.0
    
    def _analyze_depth_cues(self, image: np.ndarray) -> float:
        """Analyze depth cues for 3D face detection"""
        try:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Calculate gradient magnitude
            grad_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
            grad_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
            grad_magnitude = np.sqrt(grad_x**2 + grad_y**2)
            
            # Analyze gradient distribution
            grad_variance = np.var(grad_magnitude)
            
            # Normalize score
            depth_score = min(1.0, grad_variance / 1000.0)
            
            return depth_score
            
        except Exception as e:
            self.logger.error(f"Error analyzing depth cues: {e}")
            return 0.0
