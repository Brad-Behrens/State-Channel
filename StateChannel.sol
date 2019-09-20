pragma solidity ^0.5.11;

/// @author Brad Behrens
/// @title State Channel proof-of-concept implementation.
/// @dev Solidity state channel smart contract to be integrated into decentralised applications.

contract StateChannel {
    
    // State Channel Variables.

    // Three modes of SC operation.
    enum Status {ON, DISPUTE, OFF}
    Status public status;

    // Array of channel partipants addresses.
    address[] public channelParticipants;
    
    // Dispute struct datatype.
    struct Dispute {
        uint256 disputeRound;
        uint256 disputeStart;
        uint256 disputeEnd;
    }
    
    Dispute public dispute;
    Dispute[] public disputeRecord;
    
    // State Channel variables to be valued in constructor function.
    uint256 public channelID;
    uint256 public channelRound;
    uint256 public disputeTime;
    
    uint256 public disputeLimit;
    uint256 public disputeStart;
    uint256 public disputeEnd;
    
    // Hash of the channels state.
    bytes32 public stateHash;

    // State Channel Events.
    
    // Events to notify a change in channel operation.
    event EventChannelInitiated(uint256 indexed channelID);
    event EventDispute(uint256 indexed disputeLimit);
    event EventStateUpdate(uint256 indexed channelRound, bytes32 stateHash);
    event EventOffChain(bytes32 stateHash, uint256 indexed disputeRound);
    event EventOnChain(bytes32 stateHash, uint256 indexed disputeRound);
    event EventCloseChannel(bytes32 stateHash, uint256 indexed channelRound);
    
    
    // State chanel functions.
    
    /// @notice Constructor function that instantiates state channel.
    /// @dev Application contract to call upon constructor to initiate off-chain operation of application.
    /// @param _channelID Unique channel ID.
    /// @param _disputeTime Time specification for dispute resolution.
    /// @param _channelParticipants Addresses of the participants in the state channel.
    constructor(uint256 _channelID, uint256 _disputeTime, address[] memory _channelParticipants) public {
        // Set state channel variables.
        channelID = _channelID;
        disputeTime = _disputeTime;
        channelRound = 0;
        
        // Finalise the set of participants within the state channel.
        for (uint i = 0; i < _channelParticipants.length; i++) {
            channelParticipants.push(_channelParticipants[i]);
        }
        
        // Turn state channel operation to ON mode.
        status = Status.ON;
        
        // Notify that the state channel is now operational.
        emit EventChannelInitiated(channelID);
    }
    

    /// @notice Function that verifies digital signatures using ECDSA.
    /// @dev Used in the authorisation of new state updates in the off-chain message protocol.
    /// @param publicKey The address of a channel participant.
    /// @param h 32-byte cryptographic hash.
    /// @param v Last byte of digital signature.
    /// @param r First 32-bytes of digital signature.
    /// @param s Second 32-bytes of digital signature.
    function verifySignatures(address publicKey, bytes32 h, uint8 v, bytes32 r, bytes32 s) public pure { 
        
        // Retrieve the address of the participant from a digitalsignature.
        address signer = ecrecover(h, v, r, s);
        
        // Return error if address is not the public key.
        if (publicKey != signer) {
            revert();
        }
    }
    
    
    /// @notice Function to update the state of the channel via the off-chain message protocol.
    /// @dev Employs verifiesSignatures() function to re-compute participants digital signatures for verification.
    /// @param _stateHash The new proposed state hash via a state transition function from the application contract.
    /// @param _channelRound The new channel round with the corresponding new state hash.
    /// @param signatures The list of digital signatures of the channel participants.
    function updateState(bytes32 _stateHash, uint256 _channelRound, uint256[] memory signatures) public {
        
        // Requirement to update channel state.
        require(status == Status.ON);
        
        // Ensure the round to be updated is the next round.
        require(_channelRound == channelRound + 1);
        
        // String prefix required for ecrecover function in signature verification.
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        
        // Hash of new state of state channel.
        bytes32 newStateHash = keccak256(abi.encodePacked(_stateHash, _channelRound, address(this)));
        newStateHash = keccak256(abi.encodePacked(prefix, newStateHash));
        
        // Verify all participants have signed new state hash.
        for(uint i = 0; i < channelParticipants.length; i++) {
            uint8 V = uint8(signatures[i*3+0]) + 27;
            bytes32 R = bytes32(signatures[i*3+1]);
            bytes32 S = bytes32(signatures[i*3+2]);
            verifySignatures(channelParticipants[i], newStateHash, V, R, S);
        }
        
        // Store the new authorised state update.
        stateHash = newStateHash;
        channelRound = _channelRound;
        
        // Notify channel participants of new authorised state hash and round update.
        emit EventStateUpdate(channelRound, stateHash);
    }
    
    
    // DISPUTE RESOLUTION MODEL
      
    /// @notice Function to initiate the dispute resolution protocol.
    /// @dev Changes the channel operation to dispute mode and triggers dispute limit.
    function triggerDispute() public {
        
        // SC must be on ON operation to change operation to DISPUTE.
        require(status == Status.ON);
        
        // SC change operation to dispute.
        status = Status.DISPUTE;
        
        // Calculate the disputeLimit to be broadcasted to the SC.
        disputeStart = block.timestamp;
        disputeLimit = block.number + disputeTime;
        
        //Broadcast EventDispute to the channel participants to notify change in SC operation.
        emit EventDispute(disputeLimit);
    }
    
    
    /// @notice Function to resolve the dispute within the state channel.
    /// @dev Second attempt at re-verifying digital signatures from channel participants before the dispute time is exceeded.
    /// @param _stateHash The hash of the proposed state update.
    /// @ _channelRound Corresponding round of neew proposed state hash.
    function resolveDisputeOffChain(bytes32 _stateHash, uint256 _channelRound) public {
        // SC must be in dispute operation.
        require(status == Status.DISPUTE);
        
        // The dispute limit must not have been exceeded.
        require(block.number < disputeLimit);
        
        // Re-sign the latest state hash attempt.
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 disputeStateHash = keccak256(abi.encodePacked("resolveDisputeOffChain", _stateHash, _channelRound, address(this)));
        
        disputeStateHash = keccak256(abi.encodePacked(prefix, disputeStateHash));
        
        // Verifty all channel participants have signed latest state hash.
        for(uint i = 0; i < channelParticipants.length; i++) {
            uint8 V = uint8(i*3+0) + 27;
            bytes32 R = bytes32(i*3+1);
            bytes32 S = bytes32(i*3+2);
            verifySignatures(channelParticipants[i], disputeStateHash, V, R, S);
        }
        
        // Store latest state hash and round number.
        stateHash = disputeStateHash;
        channelRound = _channelRound;
        
        // Record dispute.
        uint256 disputeRound = channelRound;
        
        dispute = Dispute(disputeRound, disputeStart, disputeEnd);
        disputeRecord.push(dispute);
        
        // Broadcast that dispute has been resolve within the channel and revert back to ON operation.
        status = Status.ON;
        emit EventOffChain(stateHash, channelRound);
    }
    
    
    /// @notice Function that resolves dispute on-chain.
    /// @dev Once dispute time is expired, participants have the ability to close channel with latest verified state hash.
    function resolveDisputeOnChain() public {
        // SC must be in dispute operation.
        require(status == Status.DISPUTE);
        
        // The dispute limit must have expired.
        require(block.number > disputeLimit);
        
        // Store latest authorised state hash and channel round.
        stateHash = stateHash;
        channelRound = channelRound;

        // Disable SC functionality to protect state deposits.
        status = Status.OFF;
        
        // Submit latest verified round and state hash on-chain.
        emit EventOnChain(stateHash, channelRound);
    }
    

    // CLOSE STATE CHANNEL PROTOCOL
    
    /// @notice Function to initiate the closing channel protocol.
    /// @dev Requires all disputes to be resolved to ensure channel consensus.
    /// @param _stateHash Latest authorised state hash in the state channel.
    /// @param _channelRound Corresponding authorised channel round.
    /// @param signatures The digital signatures of the channel participants.
    function closeChannel(bytes32 _stateHash, uint256 _channelRound, uint256[] memory signatures) public {
        // Check to see if the State Channel isn't closed or in Dispute mode.
        require(status == Status.ON);
        
        // Cryptographically sign closing messages.
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 finalisedStateHash = keccak256(abi.encodePacked("closechannel", _stateHash, _channelRound, address(this)));
        
        finalisedStateHash = keccak256(abi.encodePacked(prefix, finalisedStateHash));
        
        // Verify all channel participants have signed
        for(uint i = 0; i < channelParticipants.length; i++) {
            uint8 V = uint8(signatures[i*3+0]) + 27;
            bytes32 R = bytes32(signatures[i*3+1]);
            bytes32 S = bytes32(signatures[i*3+2]);
            verifySignatures(channelParticipants[i], finalisedStateHash, V, R, S);
        }
        
        // Store the latest State Channel metrics to be submitted on-chain.
        stateHash = finalisedStateHash;
        channelRound = _channelRound;
        
        // Close channel and notify that the State channel is now closed.
        status = Status.OFF;
        emit EventCloseChannel(stateHash, _channelRound);
    }
    
    
    // GETTER FUNCTIONS.
    
    /// @notice Function to retrieve the number of state channel participants.
    /// @return uint
    function getChannelParticipants() public view returns(uint) {
        return channelParticipants.length;
    }
    

    /// @notice Function to retrieve the address of a specific channel participant.
    /// @param i Index value of the channel participants address array.
    /// @return address
    function getChannelParticipant(uint i) public view returns(address) {
        return channelParticipants[i];
    }
    
    /// @notice Function to retrieve the state channels unique ID.
    /// @return uint256
    function getChannelID() public view returns(uint256) {
        return channelID;
    }
    

    /// @notice Function that returns the address from their digital signature.
    /// @param h 32-byte cryptographic hash.
    /// @param v Last byte of digital signature.
    /// @param r First 32-bytes of digital signature.
    /// @param s Second 32-bytes of digital signature.
    /// @return address
    function getAddressECDSA(bytes32 h, uint8 v, bytes32 r, bytes32 s) public view returns(address) {
        address signer = ecrecover(h, v, r, s);
        
        return signer;
    }
    
    
    /// @notice Function that returns the latest authorised state hash.
    /// @return bytes32
    function getStateHash() public view returns(bytes32) {
        return stateHash;
    }
    

    /// @notice Function that returns the dispute struct and it's fields.
    /// @return uint256, uint256, uint256
    function getDispute() public view returns(uint256, uint256, uint256) {
        return(dispute.disputeRound, dispute.disputeStart, dispute.disputeEnd);
    }
    
    /// @notice Function that returns the channels status.
    /// @return uint
    function getChannelStatus() public view returns(uint) {
        return uint(status);
    }
}
