const axios = require("axios");
const https = require("https");

const api = axios.create({
  baseURL: "https://localhost:8834",
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  headers: {
    "X-ApiKeys": "accessKey=fb3540c6415b10ba5fdedf98e14526fdacb8248c20f970d31248e83da5b31e49; secretKey=73ba130dc3105d944c01675ede2cb24a52f466f0214f67625a348fcfcf48a17c",
    "Content-Type": "application/json"
  }
});

async function test() {
  try {
    const res = await api.get("/server/status");
    console.log(res.data);
  } catch (err) {
    console.error(err.response?.data || err.message);
  }
}

test();