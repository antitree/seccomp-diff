async function runSeccompDiff() {
    try {
        console.log("Running seccomp diff...");
        const response = await fetch('/run_seccomp_diff', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ containers: selectedContainers })
        });

        if (!response.ok) {
            throw new Error(`Error running seccomp diff: ${response.statusText}`);
        }

        const data = await response.json();
        console.log("Seccomp diff result:", data);

        const outputElem = document.getElementById('output');
        outputElem.innerHTML = ''; // Clear previous output

        if (data.output) {
            const tableData = JSON.parse(data.output);
            const { headers, rows, full } = tableData;

            // Create a table to display the JSON output
            const table = document.createElement('table');
            table.className = "table table-bordered";

            // Add table headers
            const headerRow = document.createElement('tr');
            headers.forEach((headerText, index) => {
                const th = document.createElement('th');
                th.textContent = headerText;
                
                
                //const fullContent = full && full[index] ? full[index] : null;
                const formattedContent = [];
                const col = index - 1
                if (full[col] != null && Array.isArray(full[col])){
                    formattedContent[col] = full[col].map(line => `<div>${line}</div>`).join('');
                    th.style.cursor = "pointer";
                    console.log(`Formatted content for ${headerText}:`, formattedContent[col]);
                    th.onclick = () => {
                        if (formattedContent[col]) {
                            showModal(`<pre>${formattedContent[col]}</pre>`);
                        } else {
                            showModal("No content available for this header.");
                        }
                    };
                }
                headerRow.appendChild(th);
            });
            table.appendChild(headerRow);

            // Add table rows
            rows.forEach((row, rowIndex) => {
                const tr = document.createElement('tr');
                row.forEach((cell, index) => {
                    const td = document.createElement('td');

                    // Check for style indicators like [b], [red]

                    const styleMatch = cell && cell.match(/^\[(\w+)](.*)$/);
                    if (styleMatch) {
                        const style = styleMatch[1].toLowerCase();
                        const content = styleMatch[2];

                        if (style === 'b') {
                            td.innerHTML = `<strong>${content}</strong>`;
                        } else if (style === 'red') {
                            td.style.color = 'red';
                            td.textContent = content;
                        } else {
                            td.textContent = content;
                        }
                    } else if (cell === null || cell === "") {
                        // Handle null or blank values
                        td.textContent = "";
                    } else {
                        td.textContent = cell;
                    }

                    // Handle JSON in the second row
                    if (rowIndex === 0 && isValidJson(cell)) {
                        const jsonContent = JSON.parse(cell);
                        const prettyJson = JSON.stringify(jsonContent, null, 2);
                        const lines = prettyJson.split('\n');

                        if (lines.length > 5) {
                            const truncated = lines.slice(0, 5).join('\n') + '\n...';
                            td.innerHTML = `<pre class="json-truncated">${truncated}<span class="ellipsis">More</span></pre>`;
                            td.style.cursor = "pointer";
                            td.onclick = () => showModal(`<pre>${prettyJson}</pre>`);
                        } else {
                            td.innerHTML = `<pre>${prettyJson}</pre>`;
                        }
                    } else if (index === 0 && rowIndex > 1) { // First column (Syscall) with modal for tooltip, skipping first two rows
                        const link = document.createElement('a');
                        link.href = "#";
                        link.textContent = cell;
                        link.onclick = (e) => {
                            e.preventDefault();
                            fetchStaticHtml(cell);
                        };
                        td.innerHTML = "";
                        td.appendChild(link);
                    }

                    tr.appendChild(td);
                });
                table.appendChild(tr);
            });

            outputElem.appendChild(table);
        } else {
            console.error("Error data from server:", data);
            outputElem.textContent = `Error: ${data.error}`;
        }
    } catch (error) {
        console.error("Error occurred while running seccomp diff:", error);
        alert(`Error: ${error.message}`);
    }
}

async function fetchStaticHtml(syscall) {
    try {
        const response = await fetch(`/syscalls/${syscall}.html`);
        if (!response.ok) {
            throw new Error(`Error fetching static content for ${syscall}: ${response.statusText}`);
        }

        const content = await response.text();
        showModal(content);
    } catch (error) {
        console.error("Error fetching static HTML content:", error);
        alert(`Error: ${error.message}`);
    }
}

