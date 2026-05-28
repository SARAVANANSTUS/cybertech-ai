const { exec } = require("child_process");
const xml2js = require("xml2js");

function runNmap(target) {

  return new Promise((resolve, reject) => {

    const command = `nmap -sV -oX - ${target}`;

    exec(command, async (error, stdout, stderr) => {

      if (error) {
        console.error("Nmap Error:", error);
        return reject(error);
      }

      try {

        const parser = new xml2js.Parser();
        const result = await parser.parseStringPromise(stdout);

        const hosts = result.nmaprun.host || [];

        let vulnerabilities = [];

        hosts.forEach(host => {

          const ports = host.ports?.[0]?.port || [];

          ports.forEach(p => {

            const service = p.service?.[0]?.$.name || "unknown";

            vulnerabilities.push({
              tool: "nmap",
              port: p.$.portid,
              protocol: p.$.protocol,
              service: service,
              severity: "info",
              description: `Service ${service} running on port ${p.$.portid}`
            });

          });

        });

        resolve({
          target,
          tool: "nmap",
          vulnerabilities
        });

      } catch (err) {
        reject(err);
      }

    });

  });
}

module.exports = {
  runNmap
};