// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

// Core Identity Registry Contract
contract IdentityRegistry is AccessControl, ReentrancyGuard, Pausable {
    using Counters for Counters.Counter;
    
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    
    Counters.Counter private _identityIds;
    
    struct BiometricData {
        bytes32 facialHash;
        bytes32 fingerprintHash;
        bytes32 voiceHash;
        bytes32 irisHash;
        bytes32 behavioralHash;
        bytes32 dnaHash;
        uint256 timestamp;
        bool isActive;
    }
    
    struct Identity {
        string did;
        address owner;
        BiometricData biometrics;
        mapping(string => bytes32) credentials;
        mapping(address => bool) authorizedVerifiers;
        uint256 reputationScore;
        uint256 createdAt;
        uint256 lastVerified;
        bool isActive;
        string[] credentialTypes;
    }
    
    mapping(address => uint256) public addressToIdentityId;
    mapping(uint256 => Identity) public identities;
    mapping(string => uint256) public didToIdentityId;
    mapping(bytes32 => bool) public usedBiometricHashes;
    
    event IdentityRegistered(uint256 indexed identityId, address indexed owner, string did);
    event IdentityVerified(uint256 indexed identityId, address indexed verifier);
    event BiometricUpdated(uint256 indexed identityId, string biometricType);
    event CredentialAdded(uint256 indexed identityId, string credentialType);
    event ReputationUpdated(uint256 indexed identityId, uint256 newScore);
    
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }
    
    function registerIdentity(
        string memory _did,
        BiometricData memory _biometrics
    ) external nonReentrant whenNotPaused {
        require(addressToIdentityId[msg.sender] == 0, "Identity already exists");
        require(didToIdentityId[_did] == 0, "DID already exists");
        require(_validateBiometrics(_biometrics), "Invalid biometric data");
        
        _identityIds.increment();
        uint256 identityId = _identityIds.current();
        
        Identity storage identity = identities[identityId];
        identity.did = _did;
        identity.owner = msg.sender;
        identity.biometrics = _biometrics;
        identity.reputationScore = 100; // Starting reputation
        identity.createdAt = block.timestamp;
        identity.lastVerified = block.timestamp;
        identity.isActive = true;
        
        addressToIdentityId[msg.sender] = identityId;
        didToIdentityId[_did] = identityId;
        
        _markBiometricsAsUsed(_biometrics);
        
        emit IdentityRegistered(identityId, msg.sender, _did);
    }
    
    function verifyIdentity(
        uint256 _identityId,
        BiometricData memory _biometrics
    ) external onlyRole(VERIFIER_ROLE) returns (bool) {
        require(identities[_identityId].isActive, "Identity not active");
        
        Identity storage identity = identities[_identityId];
        bool verified = _verifyBiometrics(identity.biometrics, _biometrics);
        
        if (verified) {
            identity.lastVerified = block.timestamp;
            identity.reputationScore = _calculateReputationIncrease(identity.reputationScore);
            emit IdentityVerified(_identityId, msg.sender);
        }
        
        return verified;
    }
    
    function updateBiometrics(
        uint256 _identityId,
        BiometricData memory _newBiometrics,
        string memory _biometricType
    ) external {
        require(identities[_identityId].owner == msg.sender, "Not authorized");
        require(_validateBiometrics(_newBiometrics), "Invalid biometric data");
        
        Identity storage identity = identities[_identityId];
        
        // Remove old biometric hashes from used list
        _removeBiometricsFromUsed(identity.biometrics);
        
        // Update biometrics
        identity.biometrics = _newBiometrics;
        _markBiometricsAsUsed(_newBiometrics);
        
        emit BiometricUpdated(_identityId, _biometricType);
    }
    
    function addCredential(
        uint256 _identityId,
        string memory _credentialType,
        bytes32 _credentialHash
    ) external onlyRole(ISSUER_ROLE) {
        require(identities[_identityId].isActive, "Identity not active");
        
        Identity storage identity = identities[_identityId];
        identity.credentials[_credentialType] = _credentialHash;
        identity.credentialTypes.push(_credentialType);
        
        emit CredentialAdded(_identityId, _credentialType);
    }
    
    function getIdentityByAddress(address _owner) external view returns (
        uint256 identityId,
        string memory did,
        uint256 reputationScore,
        uint256 createdAt,
        uint256 lastVerified,
        bool isActive
    ) {
        uint256 id = addressToIdentityId[_owner];
        require(id != 0, "Identity not found");
        
        Identity storage identity = identities[id];
        return (
            id,
            identity.did,
            identity.reputationScore,
            identity.createdAt,
            identity.lastVerified,
            identity.isActive
        );
    }
    
    function _validateBiometrics(BiometricData memory _biometrics) internal view returns (bool) {
        return (
            _biometrics.facialHash != bytes32(0) &&
            _biometrics.fingerprintHash != bytes32(0) &&
            !usedBiometricHashes[_biometrics.facialHash] &&
            !usedBiometricHashes[_biometrics.fingerprintHash]
        );
    }
    
    function _verifyBiometrics(
        BiometricData memory _stored,
        BiometricData memory _provided
    ) internal pure returns (bool) {
        uint256 matches = 0;
        uint256 totalChecks = 0;
        
        if (_stored.facialHash != bytes32(0)) {
            totalChecks++;
            if (_stored.facialHash == _provided.facialHash) matches++;
        }
        
        if (_stored.fingerprintHash != bytes32(0)) {
            totalChecks++;
            if (_stored.fingerprintHash == _provided.fingerprintHash) matches++;
        }
        
        if (_stored.voiceHash != bytes32(0)) {
            totalChecks++;
            if (_stored.voiceHash == _provided.voiceHash) matches++;
        }
        
        if (_stored.irisHash != bytes32(0)) {
            totalChecks++;
            if (_stored.irisHash == _provided.irisHash) matches++;
        }
        
        if (_stored.behavioralHash != bytes32(0)) {
            totalChecks++;
            if (_stored.behavioralHash == _provided.behavioralHash) matches++;
        }
        
        // Require at least 80% match rate
        return (matches * 100) >= (totalChecks * 80);
    }
    
    function _markBiometricsAsUsed(BiometricData memory _biometrics) internal {
        if (_biometrics.facialHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.facialHash] = true;
        }
        if (_biometrics.fingerprintHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.fingerprintHash] = true;
        }
        if (_biometrics.voiceHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.voiceHash] = true;
        }
        if (_biometrics.irisHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.irisHash] = true;
        }
        if (_biometrics.behavioralHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.behavioralHash] = true;
        }
        if (_biometrics.dnaHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.dnaHash] = true;
        }
    }
    
    function _removeBiometricsFromUsed(BiometricData memory _biometrics) internal {
        if (_biometrics.facialHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.facialHash] = false;
        }
        if (_biometrics.fingerprintHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.fingerprintHash] = false;
        }
        if (_biometrics.voiceHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.voiceHash] = false;
        }
        if (_biometrics.irisHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.irisHash] = false;
        }
        if (_biometrics.behavioralHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.behavioralHash] = false;
        }
        if (_biometrics.dnaHash != bytes32(0)) {
            usedBiometricHashes[_biometrics.dnaHash] = false;
        }
    }
    
    function _calculateReputationIncrease(uint256 _currentScore) internal pure returns (uint256) {
        if (_currentScore < 900) {
            return _currentScore + 10;
        } else if (_currentScore < 950) {
            return _currentScore + 5;
        } else {
            return _currentScore + 1;
        }
    }
}

// Credential Verification Contract
contract CredentialVerification is AccessControl, ReentrancyGuard {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    
    struct Credential {
        uint256 identityId;
        string credentialType;
        bytes32 credentialHash;
        address issuer;
        uint256 issuedAt;
        uint256 expiresAt;
        bool isActive;
        string metadataUri;
    }
    
    mapping(bytes32 => Credential) public credentials;
    mapping(uint256 => bytes32[]) public identityCredentials;
    mapping(string => mapping(uint256 => bytes32)) public typeToIdentityCredential;
    
    event CredentialIssued(bytes32 indexed credentialId, uint256 indexed identityId, string credentialType);
    event CredentialRevoked(bytes32 indexed credentialId, uint256 indexed identityId);
    event CredentialVerified(bytes32 indexed credentialId, address indexed verifier);
    
    function issueCredential(
        uint256 _identityId,
        string memory _credentialType,
        bytes32 _credentialHash,
        uint256 _expiresAt,
        string memory _metadataUri
    ) external onlyRole(ISSUER_ROLE) returns (bytes32) {
        bytes32 credentialId = keccak256(abi.encodePacked(
            _identityId,
            _credentialType,
            _credentialHash,
            msg.sender,
            block.timestamp
        ));
        
        require(credentials[credentialId].issuer == address(0), "Credential already exists");
        
        credentials[credentialId] = Credential({
            identityId: _identityId,
            credentialType: _credentialType,
            credentialHash: _credentialHash,
            issuer: msg.sender,
            issuedAt: block.timestamp,
            expiresAt: _expiresAt,
            isActive: true,
            metadataUri: _metadataUri
        });
        
        identityCredentials[_identityId].push(credentialId);
        typeToIdentityCredential[_credentialType][_identityId] = credentialId;
        
        emit CredentialIssued(credentialId, _identityId, _credentialType);
        return credentialId;
    }
    
    function verifyCredential(bytes32 _credentialId) external view returns (bool) {
        Credential memory credential = credentials[_credentialId];
        
        return (
            credential.issuer != address(0) &&
            credential.isActive &&
            credential.expiresAt > block.timestamp
        );
    }
    
    function revokeCredential(bytes32 _credentialId) external {
        require(
            credentials[_credentialId].issuer == msg.sender || 
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Not authorized"
        );
        
        credentials[_credentialId].isActive = false;
        emit CredentialRevoked(_credentialId, credentials[_credentialId].identityId);
    }
    
    function getCredentialsByIdentity(uint256 _identityId) external view returns (bytes32[] memory) {
        return identityCredentials[_identityId];
    }
    
    function getCredentialByType(
        string memory _credentialType,
        uint256 _identityId
    ) external view returns (bytes32) {
        return typeToIdentityCredential[_credentialType][_identityId];
    }
}

// Reputation System Contract
contract ReputationSystem is AccessControl, ReentrancyGuard {
    bytes32 public constant REPUTATION_UPDATER_ROLE = keccak256("REPUTATION_UPDATER_ROLE");
    
    struct ReputationRecord {
        uint256 identityId;
        uint256 score;
        uint256 totalVerifications;
        uint256 successfulVerifications;
        uint256 failedVerifications;
        uint256 lastUpdated;
        mapping(string => uint256) categoryScores;
    }
    
    mapping(uint256 => ReputationRecord) public reputationRecords;
    mapping(uint256 => string[]) public identityCategories;
    
    event ReputationUpdated(uint256 indexed identityId, uint256 newScore);
    event CategoryScoreUpdated(uint256 indexed identityId, string category, uint256 score);
    
    function updateReputationScore(
        uint256 _identityId,
        bool _verificationSuccess,
        string memory _category
    ) external onlyRole(REPUTATION_UPDATER_ROLE) {
        ReputationRecord storage record = reputationRecords[_identityId];
        
        if (record.identityId == 0) {
            record.identityId = _identityId;
            record.score = 100; // Starting score
        }
        
        record.totalVerifications++;
        record.lastUpdated = block.timestamp;
        
        if (_verificationSuccess) {
            record.successfulVerifications++;
            record.score = _calculateScoreIncrease(record.score);
            record.categoryScores[_category] = _calculateCategoryScore(record.categoryScores[_category], true);
        } else {
            record.failedVerifications++;
            record.score = _calculateScoreDecrease(record.score);
            record.categoryScores[_category] = _calculateCategoryScore(record.categoryScores[_category], false);
        }
        
        emit ReputationUpdated(_identityId, record.score);
        emit CategoryScoreUpdated(_identityId, _category, record.categoryScores[_category]);
    }
    
    function getReputationScore(uint256 _identityId) external view returns (uint256) {
        return reputationRecords[_identityId].score;
    }
    
    function getReputationDetails(uint256 _identityId) external view returns (
        uint256 score,
        uint256 totalVerifications,
        uint256 successfulVerifications,
        uint256 failedVerifications,
        uint256 lastUpdated
    ) {
        ReputationRecord storage record = reputationRecords[_identityId];
        return (
            record.score,
            record.totalVerifications,
            record.successfulVerifications,
            record.failedVerifications,
            record.lastUpdated
        );
    }
    
    function _calculateScoreIncrease(uint256 _currentScore) internal pure returns (uint256) {
        if (_currentScore < 500) {
            return _currentScore + 20;
        } else if (_currentScore < 800) {
            return _currentScore + 10;
        } else if (_currentScore < 950) {
            return _currentScore + 5;
        } else {
            return _currentScore + 1;
        }
    }
    
    function _calculateScoreDecrease(uint256 _currentScore) internal pure returns (uint256) {
        if (_currentScore > 800) {
            return _currentScore - 5;
        } else if (_currentScore > 500) {
            return _currentScore - 10;
        } else if (_currentScore > 100) {
            return _currentScore - 15;
        } else {
            return _currentScore;
        }
    }
    
    function _calculateCategoryScore(uint256 _currentScore, bool _success) internal pure returns (uint256) {
        if (_currentScore == 0) {
            _currentScore = 100;
        }
        
        if (_success) {
            return _currentScore < 950 ? _currentScore + 10 : _currentScore + 1;
        } else {
            return _currentScore > 50 ? _currentScore - 20 : _currentScore;
        }
    }
}
