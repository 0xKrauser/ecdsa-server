const express = require("express");
const app = express();
const cors = require("cors");
const port = process.env.SERVER_PORT || 3042;

const { secp256k1 } = require("ethereum-cryptography/secp256k1");
const { utf8ToBytes, toHex } = require("ethereum-cryptography/utils");
const { keccak256 } = require("ethereum-cryptography/keccak");

app.use(cors());
app.use(express.json());

const nonces = {};

const balances = {
	"0x0fc3e79116ac73aa7d58e715d2ca3ec6495471a3": 100,
};

function deriveAddress(publicKey) {
	const hash = keccak256(publicKey.slice(1));
	const address = toHex(hash.slice(-20));
	return address;
}

app.get("/balance/:address", (req, res) => {
	const { address } = req.params;
	const balance = balances[address] || 0;
	res.send({ balance });
});

app.get("/nonce/:address", (req, res) => {
	const { address } = req.params;
	const nonce = nonces[address] || 0;
	res.send({ nonce });
});

const seed = (sender, signature, message) => {
	const messageNonce = message.split(`(`)[1].split(`)`)[0];
	const sig = new secp256k1.Signature(
		BigInt(signature.r),
		BigInt(signature.s)
	).addRecoveryBit(signature.recovery);
	const signer = sig.recoverPublicKey(keccak256(utf8ToBytes(message)));
	const signerAddress = `0x${deriveAddress(signer.toRawBytes(false))}`;

	if (signerAddress !== sender) {
		return "Invalid signature";
	}

	if (
		messageNonce !== nonces[signerAddress] &&
		!(!(signerAddress in nonces) && messageNonce === "0")
	) {
		return "Invalid nonce";
	}

	if (!nonces[sender]) {
		nonces[sender] = 1;
	} else {
		nonces[sender]++;
	}

	if (!(signerAddress in balances)) {
		balances[sender] = 100;
		return "OK";
	}

	return "Already seeded";
};

const send = (sender, signature, message) => {
	const [nonce, transfer] = message.split(`(`)[1].split(`)`)[0];
	const [recipient, amount] = transfer.split(`_`);
	const sig = new secp256k1.Signature(
		BigInt(signature.r),
		BigInt(signature.s)
	).addRecoveryBit(signature.recovery);

	const signer = sig.recoverPublicKey(keccak256(utf8ToBytes(message)));
	const signerAddress = `0x${deriveAddress(signer.toRawBytes(false))}`;

	if (signerAddress !== sender) {
		return "Invalid signature";
	}

	if (
		messageNonce !== nonces[signerAddress] &&
		!(!(signerAddress in nonces) && messageNonce === "0")
	) {
		return "Invalid nonce";
	}

	if (!nonces[sender]) {
		nonces[sender] = 1;
	} else {
		nonces[sender]++;
	}

	if (!balances[sender] || balances[sender] < amount) {
		return "Not enough funds!";
	} else {
		balances[sender] -= amount;
		balances[recipient] += amount;
		return "OK";
	}
};

app.post("/transaction", (req, res) => {
	const { sender, message, signature } = req.body;
	const type = message.split(`(`)[0];
	let response;
	switch (type) {
		case "seedMe":
			response = seed(sender, JSON.parse(signature), message);
			break;
		case "send":
			response = send(sender, JSON.parse(signature), message);
			break;
		default:
			response = "Invalid transaction type";
	}
	res.send(response);
});

app.listen(port, () => {
	console.log(`Listening on port ${port}!`);
});
