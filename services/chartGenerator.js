const { ChartJSNodeCanvas } = require("chartjs-node-canvas");
const fs = require("fs");
const path = require("path");

async function generatePieChart(vulns) {

    let high = 0, medium = 0, low = 0;

    vulns.forEach(v => {
        if (v.category === "High") high++;
        else if (v.category === "Medium") medium++;
        else low++;
    });

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
            labels: ["High", "Medium", "Low"],
            datasets: [
                {
                    data: [high, medium, low],
                    backgroundColor: [
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
                    text: "Vulnerability Severity Distribution"
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