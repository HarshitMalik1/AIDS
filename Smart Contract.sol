// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title AIDS - Advanced Identity and Data Security Smart Contract
 * @author Enhanced Security Team
 * @notice This contract manages secure identity verification using biometrics and ZK proofs
 * @dev Implements multiple security layers including biometric verification, ZK proofs, and access control
 */
contract AIDSIdentityVerification is Ownable, ReentrancyGuard, Pausable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    
    // Events
    event UserRegistered(address indexed user, bytes32 indexed identityHash, uint256 timestamp);
    event BiometricVerified(address indexed user, bytes32 indexed sessionId, uint256 timestamp);
    event ZKProofVerified(address indexed user, bytes32 indexed proofHash, uint256 timestamp);
    event AccessGranted(address indexed user, bytes32 indexed resource, uint256 timestamp);
    event AccessRevoked(address indexed user, bytes32 indexed resource, uint256 timestamp);
    event SecurityBreach(address indexed user, string reason, uint256 timestamp);
    event SystemUpgraded(address indexed oldContract, address indexed newContract, uint256 timestamp);
    
    // Structs
    struct User {
        bytes32 identityHash;           // Hash of user's identity
        bytes32 biometricHash;          // Hash of biometric template
        bytes32 zkProofCommitment;      // ZK proof commitment
        uint256 registrationTime;       // When user was registered
        uint256 lastVerification;       // Last verification timestamp
        uint256 verificationCount;      // Number of successful verifications
        bool isActive;                  // User account status
        bool isVerified;               // Biometric verification status
        mapping(bytes32 => bool) accessRights;  // Resource access rights
    }
    
    struct VerificationSession {
        address user;
        bytes32 challenge;
        uint256 createdAt;
        uint256 expiresAt;
        bool isCompleted;
        bool isValid;
    }
    
    struct ZKProof {
        bytes32 commitment;
        bytes32 challenge;
        bytes32 response;
        address prover;
        uint256 timestamp;
        bool isVerified;
    }
    
    struct AccessControl {
        bytes32 resourceId;
        address[] authorizedUsers;
        uint256 minVerificationLevel;
        uint256 maxAccessDuration;
        bool requiresZKProof;
        bool isActive;
    }
    
    // State variables
    mapping(address => User) public users;
    mapping(bytes32 => VerificationSession) public verificationSessions;
    mapping(bytes32 => ZKProof) public zkProofs;
    mapping(bytes32 => AccessControl) public accessControls;
    mapping(address => mapping(bytes32 => uint256)) public userAccessExpiry;
    
    // Security parameters
    uint256 public constant SESSION_DURATION = 300; // 5 minutes
    uint256 public constant MAX_VERIFICATION_ATTEMPTS = 3;
    uint256 public constant PROOF_VALIDITY_PERIOD = 3600; // 1 hour
    uint256 public constant MIN_VERIFICATION_INTERVAL = 60; // 1 minute
    
    // Counters and stats
    uint256 public totalUsers;
    uint256 public totalVerifications;
    uint256 public totalZKProofs;
    uint256 public securityBreaches;
    
    // Authorized verifiers
    mapping(address => bool) public authorizedVerifiers;
    
    // Modifiers
    modifier onlyAuthorizedVerifier() {
        require(authorizedVerifiers[msg.sender] || msg.sender == owner(), "Not authorized verifier");
        _;
    }
    
    modifier onlyRegisteredUser() {
        require(users[msg.sender].isActive, "User not registered");
        _;
    }
    
    modifier onlyVerifiedUser() {
        require(users[msg.sender].isVerified, "User not verified");
        _;
    }
    
    modifier validSession(bytes32 sessionId) {
        require(verificationSessions[sessionId].isValid, "Invalid session");
        require(block.timestamp <= verificationSessions[sessionId].expiresAt, "Session expired");
        _;
    }
    
    constructor() {
        authorizedVerifiers[msg.sender] = true;
    }
    
    /**
     * @notice Register a new user with biometric and ZK proof data
     * @param identityHash Hash of user's identity information
     * @param biometricHash Hash of biometric template
     * @param zkCommitment ZK proof commitment
     */
    function registerUser(
        bytes32 identityHash,
        bytes32 biometricHash,
        bytes32 zkCommitment
    ) external nonReentrant whenNotPaused {
        require(!users[msg.sender].isActive, "User already registered");
        require(identityHash != bytes32(0), "Invalid identity hash");
        require(biometricHash != bytes32(0), "Invalid biometric hash");
        require(zkCommitment != bytes32(0), "Invalid ZK commitment");
        
        // Create user record
        User storage newUser = users[msg.sender];
        newUser.identityHash = identityHash;
        newUser.biometricHash = biometricHash;
        newUser.zkProofCommitment = zkCommitment;
        newUser.registrationTime = block.timestamp;
        newUser.isActive = true;
        newUser.isVerified = false;
        
        totalUsers++;
        
        emit UserRegistered(msg.sender, identityHash, block.timestamp);
    }
    
    /**
     * @notice Initiate biometric verification session
     * @param challenge Random challenge for verification
     * @return sessionId Unique session identifier
     */
    function initiateVerification(bytes32 challenge) 
        external 
        onlyRegisteredUser 
        nonReentrant 
        whenNotPaused 
        returns (bytes32 sessionId) 
    {
        require(challenge != bytes32(0), "Invalid challenge");
        require(
            block.timestamp >= users[msg.sender].lastVerification + MIN_VERIFICATION_INTERVAL,
            "Verification too frequent"
        );
        
        // Generate unique session ID
        sessionId = keccak256(abi.encodePacked(msg.sender, challenge, block.timestamp));
        
        // Create verification session
        verificationSessions[sessionId] = VerificationSession({
            user: msg.sender,
            challenge: challenge,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + SESSION_DURATION,
            isCompleted: false,
            isValid: true
        });
        
        return sessionId;
    }
    
    /**
     * @notice Complete biometric verification
     * @param sessionId Session identifier
     * @param biometricProof Proof of biometric verification
     * @param signature Signature from authorized verifier
     */
    function completeBiometricVerification(
        bytes32 sessionId,
        bytes32 biometricProof,
        bytes memory signature
    ) external onlyAuthorizedVerifier validSession(sessionId) nonReentrant whenNotPaused {
        VerificationSession storage session = verificationSessions[sessionId];
        require(!session.isCompleted, "Session already completed");
        
        address user = session.user;
        
        // Verify signature
        bytes32 messageHash = keccak256(abi.encodePacked(sessionId, biometricProof, user));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessageHash.recover(signature);
        require(authorizedVerifiers[signer], "Invalid signature");
        
        // Update user verification status
        users[user].isVerified = true;
        users[user].lastVerification = block.timestamp;
        users[user].verificationCount++;
        
        // Mark session as completed
        session.isCompleted = true;
        
        totalVerifications++;
        
        emit BiometricVerified(user, sessionId, block.timestamp);
    }
    
    /**
     * @notice Submit and verify ZK proof
     * @param commitment ZK proof commitment
     * @param challenge ZK proof challenge
     * @param response ZK proof response
     * @return proofHash Hash of the verified proof
     */
    function submitZKProof(
        bytes32 commitment,
        bytes32 challenge,
        bytes32 response
    ) external onlyRegisteredUser nonReentrant whenNotPaused returns (bytes32 proofHash) {
        require(commitment != bytes32(0), "Invalid commitment");
        require(challenge != bytes32(0), "Invalid challenge");
        require(response != bytes32(0), "Invalid response");
        
        // Verify ZK proof (simplified - in production, use proper ZK verification)
        bool isValid = verifyZKProof(msg.sender, commitment, challenge, response);
        require(isValid, "Invalid ZK proof");
        
        // Create proof hash
        proofHash = keccak256(abi.encodePacked(commitment, challenge, response, msg.sender));
        
        // Store proof
        zkProofs[proofHash] = ZKProof({
            commitment: commitment,
            challenge: challenge,
            response: response,
            prover: msg.sender,
            timestamp: block.timestamp,
            isVerified: isValid
        });
        
        totalZKProofs++;
        
        emit ZKProofVerified(msg.sender, proofHash, block.timestamp);
        
        return proofHash;
    }
    
    /**
     * @notice Grant access to a resource
     * @param user User address
     * @param resourceId Resource identifier
     * @param duration Access duration in seconds
     */
    function grantAccess(
        address user,
        bytes32 resourceId,
        uint256 duration
    ) external onlyAuthorizedVerifier nonReentrant whenNotPaused {
        require(users[user].isActive, "User not registered");
        require(users[user].isVerified, "User not verified");
        require(resourceId != bytes32(0), "Invalid resource ID");
        require(duration > 0, "Invalid duration");
        
        // Check if resource requires ZK proof
        if (accessControls[resourceId].requiresZKProof) {
            require(hasValidZKProof(user), "Valid ZK proof required");
        }
        
        // Grant access
        users[user].accessRights[resourceId] = true;
        userAccessExpiry[user][resourceId] = block.timestamp + duration;
        
        emit AccessGranted(user, resourceId, block.timestamp);
    }
    
    /**
     * @notice Revoke access to a resource
     * @param user User address
     * @param resourceId Resource identifier
     */
    function revokeAccess(
        address user,
        bytes32 resourceId
    ) external onlyAuthorizedVerifier nonReentrant whenNotPaused {
        users[user].accessRights[resourceId] = false;
        userAccessExpiry[user][resourceId] = 0;
        
        emit AccessRevoked(user, resourceId, block.timestamp);
    }
    
    /**
     * @notice Check if user has access to a resource
     * @param user User address
     * @param resourceId Resource identifier
     * @return hasAccess Whether user has access
     */
    function hasAccess(address user, bytes32 resourceId) external view returns (bool hasAccess) {
        if (!users[user].isActive || !users[user].isVerified) {
            return false;
        }
        
        if (!users[user].accessRights[resourceId]) {
            return false;
        }
        
        if (block.timestamp > userAccessExpiry[user][resourceId]) {
            return false;
        }
        
        return true;
    }
    
    /**
     * @notice Create access control for a resource
     * @param resourceId Resource identifier
     * @param minVerificationLevel Minimum verification level required
     * @param maxAccessDuration Maximum access duration
     * @param requiresZKProof Whether ZK proof is required
     */
    function createAccessControl(
        bytes32 resourceId,
        uint256 minVerificationLevel,
        uint256 maxAccessDuration,
        bool requiresZKProof
    ) external onlyOwner {
        accessControls[resourceId] = AccessControl({
            resourceId: resourceId,
            authorizedUsers: new address[](0),
            minVerificationLevel: minVerificationLevel,
            maxAccessDuration: maxAccessDuration,
            requiresZKProof: requiresZKProof,
            isActive: true
        });
    }
    
    /**
     * @notice Add authorized verifier
     * @param verifier Address of the verifier
     */
    function addAuthorizedVerifier(address verifier) external onlyOwner {
        require(verifier != address(0), "Invalid verifier address");
        authorizedVerifiers[verifier] = true;
    }
    
    /**
     * @notice Remove authorized verifier
     * @param verifier Address of the verifier
     */
    function removeAuthorizedVerifier(address verifier) external onlyOwner {
        authorizedVerifiers[verifier] = false;
    }
    
    /**
     * @notice Emergency pause contract
     */
    function pause() external onlyOwner {
        _pause();
    }
    
    /**
     * @notice Unpause contract
     */
    function unpause() external onlyOwner {
        _unpause();
    }
    
    /**
     * @notice Report security breach
     * @param user User involved in breach
     * @param reason Reason for breach
     */
    function reportSecurityBreach(address user, string memory reason) external onlyAuthorizedVerifier {
        users[user].isVerified = false;
        securityBreaches++;
        
        emit SecurityBreach(user, reason, block.timestamp);
    }
    
    /**
     * @notice Get user information
     * @param user User address
     * @return User information struct
     */
    function getUserInfo(address user) external view returns (
        bytes32 identityHash,
        uint256 registrationTime,
        uint256 lastVerification,
        uint256 verificationCount,
        bool isActive,
        bool isVerified
    ) {
        User storage userData = users[user];
        return (
            userData.identityHash,
            userData.registrationTime,
            userData.lastVerification,
            userData.verificationCount,
            userData.isActive,
            userData.isVerified
        );
    }
    
    /**
     * @notice Get system statistics
     * @return System statistics
     */
    function getSystemStats() external view returns (
        uint256 _totalUsers,
        uint256 _totalVerifications,
        uint256 _totalZKProofs,
        uint256 _securityBreaches
    ) {
        return (totalUsers, totalVerifications, totalZKProofs, securityBreaches);
    }
    
    /**
     * @notice Verify ZK proof (simplified implementation)
     * @param user User address
     * @param commitment Proof commitment
     * @param challenge Proof challenge
     * @param response Proof response
     * @return isValid Whether proof is valid
     */
    function verifyZKProof(
        address user,
        bytes32 commitment,
        bytes32 challenge,
        bytes32 response
    ) internal view returns (bool isValid) {
        // Simplified ZK proof verification
        // In production, implement proper zero-knowledge proof verification
        bytes32 userCommitment = users[user].zkProofCommitment;
        bytes32 expectedResponse = keccak256(abi.encodePacked(userCommitment, challenge));
        
        return expectedResponse == response;
    }
    
    /**
     * @notice Check if user has valid ZK proof
     * @param user User address
     * @return hasValid Whether user has valid ZK proof
     */
    function hasValidZKProof(address user) internal view returns (bool hasValid) {
        // Check if user has any recent valid ZK proof
        // This is simplified - in production, implement proper proof tracking
        return users[user].zkProofCommitment != bytes32(0);
    }
    
    /**
     * @notice Upgrade contract (placeholder for upgradability)
     * @param newContract New contract address
     */
    function upgradeContract(address newContract) external onlyOwner {
        require(newContract != address(0), "Invalid contract address");
        emit SystemUpgraded(address(this), newContract, block.timestamp);
        // Implement upgrade logic here
    }
    
    /**
     * @notice Fallback function
     */
    receive() external payable {
        revert("Contract does not accept Ether");
    }
}
