async function listContainers() {
    try {
        console.log("Fetching list of containers...");
        const response = await fetch('/list_containers', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`Error fetching containers: ${response.statusText}`);
        }

        const data = await response.json();
        console.log("Containers fetched:", data);

        allContainers = data.containers || [];
        updateNamespaceFilter();
        const nameFilter = document.getElementById('nameFilter').value.toLowerCase();
        const filteredContainers = allContainers.filter(container => container.name.toLowerCase().includes(nameFilter));
        renderContainers(filteredContainers);
        
    } catch (error) {
        console.error("Error occurred while listing containers:", error);
        alert(`Error: ${error.message}`);
    }
    
}

function isValidJson(str) {
    try {
        JSON.parse(str);
        return true;
    } catch (e) {
        return false;
    }
}

async function runDefaultDiff() {
    console.log("Running default diff...");

    const reduce = configState.get("reduce");
    const only_diff = configState.get("only_diff");
    const only_dangerous = configState.get("only_dangerous");

    console.log(selectedContainers);


    const response = await fetch('/run_seccomp_diff', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 
            containers: [selectedContainers[0], "default"],
            reduce: reduce, 
            only_diff: only_diff,
            only_dangerous: only_dangerous
         })
    });

    if (!response.ok) {
        throw new Error(`Error running seccomp diff: ${response.statusText}`);
    }

    const data = await response.json();
    console.log("Seccomp diff result:", data);

    fillDiffTable(data);

}

async function fillDiffTable(data) {
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

                    // Handle JSON in the seccomp row
                    if (rowIndex === 0 && index !== 0){
                        if (isValidJson(cell)){
                        
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
                        } else { 
                            td.innerHTML = `<pre>${cell}</pre>`;}
                        } else if (rowIndex === 1 && index !== 0 && cell !== null){
                            const fullcaps = cell;
                            const lines = cell.split('\n');
                            
                            if (lines.length > 5) {
                                const truncated = lines.slice(0, 5).join('\n') + '\n...';
                                td.innerHTML = `<pre class="json-truncated">${truncated}<span class="ellipsis">More</span></pre>`;
                                td.style.cursor = "pointer";
                                td.onclick = () => showModal(`<pre>${fullcaps}</pre>`);
                            } else {
                                td.innerHTML = `<pre>${fullcaps}</pre>`;
                            }

                    } else if (index === 0 && rowIndex > 1) { // First column (Syscall) with modal for tooltip, skipping first two rows
                        const emojiMatch = cell && cell.match(/:(\w+):/g);
                        let inject = '';
                        if (emojiMatch) {
                            let content = cell;

                            // Map of emoji names to their corresponding Bootstrap icons
                            const emojiMap = {
                                warning: '<i class="bi bi-exclamation-triangle-fill highlight"></i>',
                                smile: '<i class="bi bi-emoji-smile highlight"></i>',
                                heart: '<i class="bi bi-heart-fill highlight"></i>',
                                thumbs_up: '<i class="bi bi-hand-thumbs-up-fill highlight"></i>',
                                fire: '<i class="bi bi-fire"></i>',
                                // Add more Bootstrap icon mappings as needed
                            };

                            emojiMatch.forEach(match => {
                                const emojiKey = match.slice(1, -1); // Remove colons, e.g., :warning: -> warning
                                if (emojiMap[emojiKey]) {
                                    inject = emojiMap[emojiKey];
                                    cell = content.replace(match, '');
                                }
                            });
                        }
                        
                        
                        const link = document.createElement('a');
                        link.href = "#";
                        link.textContent = cell;
                        link.onclick = (e) => {
                            e.preventDefault();
                            fetchStaticHtml(cell);
                        };
                        td.innerHTML = inject;
                        
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
    
}


async function runSeccompDiff() {
    try {
        console.log("Running seccomp diff...");

        const reduce = configState.get("reduce");
        const only_diff = configState.get("only_diff");
        const only_dangerous = configState.get("only_dangerous");

        console.log(`"only_dangerous" set to`, configState.get("only_dangerous")); // Debug output

        const response = await fetch('/run_seccomp_diff', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                containers: selectedContainers,
                reduce: reduce, 
                only_diff: only_diff,
                only_dangerous: only_dangerous
             })
        });

        if (!response.ok) {
            throw new Error(`Error running seccomp diff: ${response.statusText}`);
        }

        const data = await response.json();
        console.log("Seccomp diff result:", data);

        fillDiffTable(data);

        
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

