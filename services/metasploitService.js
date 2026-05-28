const axios = require("axios");
const msgpack = require("msgpack-lite");

const RPC_URL = "http://127.0.0.1:55553/api/";
const USER = "msf";
const PASS = "msf123";

let token = null;

// Login to Metasploit RPC
async function login() {
  const payload = msgpack.encode(["auth.login", USER, PASS]);

  const res = await axios.post(RPC_URL, payload, {
    headers: { "Content-Type": "binary/message-pack" },
    responseType: "arraybuffer"
  });

  const decoded = msgpack.decode(res.data);

  if (decoded.result === "success") {
    token = decoded.token;
    console.log("✅ Metasploit Auth Success");
  } else {
    throw new Error("Metasploit login failed");
  }
}

// Run exploit / scan
async function runMetasploit(target) {
  if (!token) await login();

  const payload = msgpack.encode([
    "module.execute",
    token,
    "auxiliary",
    "scanner/portscan/tcp",
    {
      RHOSTS: target
    }
  ]);

  const res = await axios.post(RPC_URL, payload, {
    headers: { "Content-Type": "binary/message-pack" },
    responseType: "arraybuffer"
  });

  const decoded = msgpack.decode(res.data);

  console.log("Metasploit Result:", decoded);

  return decoded;
}

module.exports = {
  runMetasploit
};