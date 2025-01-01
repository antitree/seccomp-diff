let selectedContainers = [];
let allContainers = []; // To keep track of all containers for filtering
let namespaces = []; // To store available namespaces

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
        renderContainers(allContainers);
    } catch (error) {
        console.error("Error occurred while listing containers:", error);
        alert(`Error: ${error.message}`);
    }
}

function renderContainers(containers) {
    const containerDiv = document.getElementById('containers');
    containerDiv.innerHTML = '';
    
    if (containers.length > 0) {
        containers.forEach(container => {
            const button = document.createElement('button');
            button.textContent = `${container.name} (PID: ${container.pid})`;
            button.className = "btn btn-outline-primary";
            button.onclick = () => toggleSelection(container, button);
            containerDiv.appendChild(button);
        });
    } else {
        containerDiv.textContent = "No containers found.";
    }
}

function updateNamespaceFilter() {
    const namespaceFilter = document.getElementById('namespaceFilter');
    namespaces = Array.from(new Set(allContainers.map(container => container.namespace)));
    namespaceFilter.innerHTML = '<option value="">All Namespaces</option>';
    namespaces.forEach(namespace => {
        const option = document.createElement('option');
        option.value = namespace;
        option.textContent = namespace;
        namespaceFilter.appendChild(option);
    });
}

function filterByName() {
    const nameFilter = document.getElementById('nameFilter').value.toLowerCase();
    const filteredContainers = allContainers.filter(container => container.name.toLowerCase().includes(nameFilter));
    renderContainers(filteredContainers);
}

function filterByNamespace() {
    const namespaceFilter = document.getElementById('namespaceFilter').value;
    const filteredContainers = namespaceFilter ? allContainers.filter(container => container.namespace === namespaceFilter) : allContainers;
    renderContainers(filteredContainers);
}

function toggleSelection(container, button) {
    const exists = selectedContainers.find(c => c.pid === container.pid);
    if (exists) {
        selectedContainers = selectedContainers.filter(c => c.pid !== container.pid);
        button.classList.remove('selected');
    } else if (selectedContainers.length < 2) {
        selectedContainers.push(container);
        button.classList.add('selected');
    }

    document.getElementById('runDiffButton').style.display = selectedContainers.length === 2 ? 'inline-block' : 'none';
}

async function showModal(content) {
    try {
        // Create a modal
        const modal = document.createElement('div');
        modal.className = "modal fade";
        modal.id = "syscallModal";
        console.error(content)
        modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Details</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        ${content}
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Initialize and show the modal
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();

        // Cleanup modal on close
        modal.addEventListener('hidden.bs.modal', () => {
            modal.remove();
        });
    } catch (error) {
        console.error("Error displaying modal:", error);
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

function openConfigPanel() {
    document.getElementById('config-panel').classList.remove('hidden');
}

function closeConfigPanel() {
    document.getElementById('config-panel').classList.add('hidden');
}

async function updateConfig(key, value) {
    try {
        const response = await fetch('/update-config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ [key]: value }),
        });

        if (!response.ok) {
            throw new Error(`Error updating config: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Updated config:', data.config);
    } catch (error) {
        console.error('Error updating configuration:', error);
    }
}
