### Cryptographic Hash Function
##### Hash function
- takes any string as input
- fixed-size output
- efficiently computable
##### Security properties:
- collision-free
	- nobody can find x and y s.t. x!=y and H(x)=H(y)
	- collision do exist: because size of possible inputs is larger than possible outputs
	- try 2^130 randomly chosen inputs -> 99.8% chance that two of them will collide -> takes too long to matter
	- is there faster way to find collision? for simple hash function
	- no hash function proven to be collision-free
	- Application: message digest
		- if H(x) = H(y) -> x=y
		- if r is chose from a probability distribution that has high min-entropy (i.e. very spread out), then given H(r | x), it is infeasible to find x
- hiding
	- given H(x), it's infeasible to find x
	- x in a set very spead-out
	- Application: commitment
		- commit a value and reveal later
		- commitment API:
			- (com, key) := commit (msg)
			- match := verify(com, key, msg)
			- to seal: publish com
			- to open: publish key, msg -> anyone can use verify to check validity
			- security properties:
				- hiding: given H(key | msg), infeasible to find msg
				- binding: infeasible to find msg != msg' s.t. verify(commit(msg), msg') == true
			- impl:
				- commit(msg) :- ( H(key | msg), key ) where key is a random 256-bit value
					- verify(com, key, msg) := ( H(key | msg) == com)
- puzzle-friendly
	- for every possible output value y, if k is chosen from a distribution with high min-entropy, then it its infeasible to find x s.t. H(k | x) = y
	- Application: search puzzle
		- given a "puzzle ID" id (from high min-entropy distribution),
		- and a target set Y
		- try to find a "solution" x s.t. H(id | x) belongs to Y
		- property implies that ni solving strategy is much better than trying random values of x
##### SHA-256 hash function
![[Pasted image 20240401215705.png]]
- take in message, break into 512 bits in size
- (add padding if not exactly multiple of 512)
	- padding = 1 bit + some number of zero bits + end of the padding is 64 bits length field: length of the message in bits
- IV: some value in standard documents
- IV + 1st block -> function c -> outcome 256 bits -> ... -> Hash (256 bits)
- if c is collision free, entire hash function is collision free

### Hash pointers and data structures
##### hash pointer: 
- definition:
	- pointer to which some info is stored, and 
	- cryptographic hash of the info
- if we have a hash ptr, we can 1. ask to get the info back and 2. verify that info is unchanged
![[Pasted image 20240401221836.png]]

##### build data structures with hash ptr

**![[Pasted image 20240401222320.png]]
![[Pasted image 20240401222632.png]]
- if adversary want to tamper with data anywhere in the entire chain, in order to keep consistency, it needs to tamper with hash ptrs all the way back to the beginning
- it won't tamper the head, hence road block!
- genesis block: beginning of the list

![[Pasted image 20240401223009.png]]
- if want to prove some data is children of the merkle tree, only shows O(logN) items
- advantage:
	- tree holds many items, but just need to remember the root hash
	- can verify membership in O(logN) time/space
- variant:
	- sorted Merkle tree can verify non-membership in O(logN)

##### as long as no cycle, hash ptr can be used in any ptr based data structure

### Digital signatures
##### definition:
- only you can sign, anyone can verify
- signature is tied to a particular document (cannot be cut-and-pasted to another doc)

##### API
- (sk, pk) := generateKeys(keysize)
	- sk: secret signing key
	- pk: public verification key
- sig := sign(sk, message)
  above two can be randomized algorithms
- isValid := verify(pk, message, sig)

##### requirements
- "valid signatures verify"
	- verify(pk, message, sign(sk, message)) == true
- "can't forge signatures"
	- adversary who knows pk; gets to see signatures on messages of his choice
	- cannot produce a verifiable signature on another message
	- Game example:
		- allow attackers to get signatures on some documents of his choice
		- ![[Pasted image 20240401231250.png]]
		- signature is unforgeable if probability of attacker wins the game is negligible no matter what algorithm the attacker is using
	  
##### practical stuff
- algo is randomized: 
	- need good source of randomness
- limit on message size:
	- fix to use Hash(message) rather than message
- fun trick: sign a hash ptr
	- signature "covers" the whole structure
	- e.g. if u sign the end of a blockchain, the result what you would effectively signing ditally the entire blockchain
##### Fact
- bitcoin uses ECDSA standard:
	- Elliptic Curve Digital Signature Algorithm
- relies on hairy math
- good randomness is essential
	- foul this up in generateKeys() or sign() probably leaked your private key

### pk or H(pk) as identifies
##### useful trick (can be used along with signature)
- public key == an identity
- if you see sig s.t. verify(pk, msg, sig) == true, think of it as pk says, "msg"
- to "speak for" pk, you must know matching secret key sk
- you control the identity, because only you know sk; if pk "looks random", nobody needs to know who you are

##### decentralized identity management
- anybody can make a new identity at any time, make as many as you want
- no central point of coordination
- these identities are called "addresses" in bitcoin

##### Privacy
- addresses not directly connected to real-world identity -> no initial tie
- but observer can link together an address's activity over time, make inferences -> behavior pattern

### hash function + digital signatures = cryptocurrency

### GoofyCoin: A Simple Model

- **Creation of Coins**: 
  - Goofy has the authority to create new coins at will. 
  - Each new coin is represented by a data structure containing a unique coin ID and Goofy's digital signature.

- **Transaction Process**: 
  - Coin owners can transfer coins by signing a statement indicating the recipient.
  - Transactions are verified by following the chain of digital signatures.
  - Ownership is validated by the presence of valid signatures.
![[Pasted image 20240411221333.png]]
### Limitations of GoofyCoin

- **Double-Spending Attack**: 
  - The system allows for the same coin to be spent multiple times.
  - both Bob and Chunk have equally looking ownership of the coin.
  - simple but not secure
![[Pasted image 20240411221509.png]]

### ScroogeCoin

- **Addressing Double-Spending**:
  - ScroogeCoin enhances the model: introduce a blockchain, a history of all transactions, digitally signed by Scrooge.
  - ![[Pasted image 20240411221945.png]]
  - The blockchain allows for the detection of double-spending attempts.
	  - same example above, everyone will be able to see that that coin Alice has already paid to the 1st receiver;
	  - if Alice tries to pay the same to 2nd person, double spending detected
  - Transactions are recorded in blocks, forming a chain of validated transactions.

### ScroogeCoin Transactions

- **CreateCoins Transaction**: 
  - Scrooge can create new coins in a transaction, assigning them to specific recipients.
  - Each coin has a unique coin ID for tracking purposes.
  - Create transaction is always valid because Scrooge said so (if Scrooge put this block he signed, then it's valid by definition)

- **PayCoins Transaction**: 
  - Coins are consumed and destroyed in a transaction.
	    ![[Pasted image 20240411222634.png]]
  - New coins are created with equivalent total value but may belong to different recipients.
  - Transactions must be signed by all owners of the consumed coins.
  - coins are immutable: never changed; never subdivided; never combined
	  - they are only created in one transaction; and later consumed in another
	  - do the equivalent subdivide using transaction:
		  - create new trans
		  - consume your coin
		  - pay out 2 new coins to yourself

### Challenges of Centralization

- **Dependency on Scrooge**: 
  - Scrooge's integrity and continued operation are crucial for the system's functionality.
  - Centralization poses a risk to the reliability and trustworthiness of the currency.

### Moving Towards Decentralization

- **Questions**: 
  - how everyone can agree upon a single published block chain that is the agreed upon history which transactions have happened
  - how people agree which transaction are valid and which transactions have actually occurred
  - how we can assign IDs to things in a decentralized way

### HW
```java
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TxHandler {
    private UTXOPool utxoPool;

    public TxHandler(UTXOPool utxoPool) {
        // Make a defensive copy of utxoPool
        this.utxoPool = new UTXOPool(utxoPool);
    }

    public boolean isValidTx(Transaction tx) {
        Set<UTXO> utxoSet = new HashSet<>(); // To track claimed UTXOs
        double inputSum = 0;
        double outputSum = 0;

        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);

            // Check if input's UTXO is in the current pool
            if (!utxoPool.contains(utxo)) {
                return false;
            }

            // Check if the signature on the input is valid
            Transaction.Output output = utxoPool.getTxOutput(utxo);
            if (!Crypto.verifySignature(output.address, tx.getRawDataToSign(i), input.signature)) {
                return false;
            }

            // Check for double spending
            if (utxoSet.contains(utxo)) {
                return false;
            }
            utxoSet.add(utxo);

            inputSum += output.value;
        }

        for (Transaction.Output output : tx.getOutputs()) {
            // Check if all output values are non-negative
            if (output.value < 0) {
                return false;
            }
            outputSum += output.value;
        }

        // Check if the sum of input values is greater than or equal to the sum of output values
        return inputSum >= outputSum;
    }

    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> validTxs = new ArrayList<>();

        for (Transaction tx : possibleTxs) {
            if (isValidTx(tx)) {
                validTxs.add(tx);

                // Remove consumed UTXOs from the pool
                for (Transaction.Input input : tx.getInputs()) {
                    UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                    utxoPool.removeUTXO(utxo);
                }

                // Add new UTXOs to the pool
                byte[] txHash = tx.getHash();
                for (int i = 0; i < tx.numOutputs(); i++) {
                    UTXO utxo = new UTXO(txHash, i);
                    utxoPool.addUTXO(utxo, tx.getOutput(i));
                }
            }
        }

        return validTxs.toArray(new Transaction[0]);
    }
}

```

```java
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;

public class MaxFeeHandler extends TxHandler {
    public MaxFeeHandler(UTXOPool utxoPool) {
        super(utxoPool);
    }

    @Override
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        Arrays.sort(possibleTxs, Comparator.comparingDouble(this::calculateFee).reversed());

        Set<Transaction> acceptedTxs = new HashSet<>();
        for (Transaction tx : possibleTxs) {
            if (super.isValidTx(tx)) {
                acceptedTxs.add(tx);

                // Remove consumed UTXOs from the pool
                for (Transaction.Input input : tx.getInputs()) {
                    UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                    super.utxoPool.removeUTXO(utxo);
                }

                // Add new UTXOs to the pool
                byte[] txHash = tx.getHash();
                for (int i = 0; i < tx.numOutputs(); i++) {
                    UTXO utxo = new UTXO(txHash, i);
                    super.utxoPool.addUTXO(utxo, tx.getOutput(i));
                }
            }
        }

        return acceptedTxs.toArray(new Transaction[0]);
    }

    private double calculateFee(Transaction tx) {
        double inputSum = 0;
        double outputSum = 0;

        for (Transaction.Input input : tx.getInputs()) {
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            Transaction.Output output = super.utxoPool.getTxOutput(utxo);
            inputSum += output.value;
        }

        for (Transaction.Output output : tx.getOutputs()) {
            outputSum += output.value;
        }

        return inputSum - outputSum;
    }
}

```