const { ChartJSNodeCanvas } = require("chartjs-node-canvas");
const fs = require("fs");
const path = require("path");

async function generatePieChart(vulns) {

    let high = 0, medium = 0, low = 0;

    vulns.forEach(v => {
        const category = String(v?.category || "");
        const severity = Number(v?.severity ?? -1);

        if (category === "High" || severity >= 3) high++;
        else if (category === "Medium" || severity === 2) medium++;
        else low++;
    });

    const total = high + medium + low;
    const isEmpty = total === 0;

    const width = 800;
    const height = 600;

    const canvas = new ChartJSNodeCanvas({
        width,
        height,
        backgroundColour: "white"
    });

    const config = {
        type: "pie",
        data: {
            labels: isEmpty ? ["No findings"] : ["High", "Medium", "Low"],
            datasets: [
                {
                    data: isEmpty ? [1] : [high, medium, low],
                    backgroundColor: isEmpty
                        ? ["#9e9e9e"]
                        : [
                            "#ff4d4d",   
                            "#ffa500",   
                            "#4caf50"    
                        ]
                }
            ]
        },
        options: {
            plugins: {
                legend: {
                    position: "bottom"
                },
                title: {
                    display: true,
                    text: isEmpty
                        ? "Vulnerability Severity Distribution (No findings)"
                        : "Vulnerability Severity Distribution (OpenVAS + Nmap)"
                }
            }
        }
    };

    const image = await canvas.renderToBuffer(config);
    const chartsDir = path.join(__dirname, "../charts");

    if (!fs.existsSync(chartsDir)) {
        fs.mkdirSync(chartsDir);
    }

    const filePath = path.join(chartsDir, "vulnerability_pie.png");

    fs.writeFileSync(filePath, image);

    return filePath;
}

module.exports = { generatePieChart };
