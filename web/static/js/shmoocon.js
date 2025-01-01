let selectedContainers = [];
let allContainers = []; // To keep track of all containers for filtering
let namespaces = []; // To store available namespaces



// function toggleIcon(icon, option) {
//     const isEnabled = icon.classList.contains('icon-enabled');
//     if (isEnabled) {
//         icon.classList.remove('icon-enabled');
//         icon.classList.add('icon-disabled');
//         updateConfig(option, false);
//     } else {
//         icon.classList.remove('icon-disabled');
//         icon.classList.add('icon-enabled');
//         updateConfig(option, true);
//     }
// }


// Create a session storage wrapper for managing configuration state
const configState = {
    get: function(key) {
        const value = sessionStorage.getItem(key);
        return value !== null ? JSON.parse(value) : null;
    },
    set: function(key, value) {
        sessionStorage.setItem(key, JSON.stringify(value));
    },
    remove: function(key) {
        sessionStorage.removeItem(key);
    },
};

// Toggle icon state and update session storage
function toggleIcon(icon, sessionKey) {
    // Check current state
    const isEnabled = icon.classList.contains('icon-enabled');

    // Toggle icon class
    if (isEnabled) {
        icon.classList.remove('icon-enabled');
        icon.classList.add('icon-disabled');
        configState.set(sessionKey, false); // Update session storage
    } else {
        icon.classList.remove('icon-disabled');
        icon.classList.add('icon-enabled');
        configState.set(sessionKey, true); // Update session storage
    }

    console.log(`${sessionKey} set to`, configState.get(sessionKey)); // Debug output
}

// Generic function to update configuration state
function updateConfig(key, value) {
    configState.set(key, value);
    console.log(`${key} updated to`, value); // Debug output
}

// Example usage: Restore the state of toggles on page load
window.onload = function() {
    const toggles = [
        { id: 'icon1', key: 'only_diff' },
        { id: 'icon2', key: 'only_dangerous' }
    ];
    const savedMode = configState.get("mode");
    if (savedMode) {
        const modeIcon = document.getElementById('modeIcon');
        updateServerConfig("mode", savedMode);
        if (savedMode === 'k8s') {
            modeIcon.innerHTML = '<img src="images/kubernetes-icon.png" onclick="updateConfig(\'mode\', \'Docker\');updateModeIcon()" alt="Kubernetes Icon" style="width: 50px;">';
        } else if (savedMode === 'Docker') {
            modeIcon.innerHTML = '<img src="images/docker-icon.png" onclick="updateConfig(\'mode\', \'k8s\');updateModeIcon()" alt="Docker Icon" style="width: 50px;">';
        } else {
            modeIcon.innerHTML = '<img src="images/kubernetes-icon.png" onclick="updateConfig(\'mode\', \'k8s\');updateModeIcon()" alt="Docker Icon" style="width: 50px;">';
        }
    }

    

    toggles.forEach(toggle => {
        const element = document.getElementById(toggle.id);
        const storedState = configState.get(toggle.key);

        if (storedState !== null) {
            element.classList.toggle('icon-enabled', storedState);
            element.classList.toggle('icon-disabled', !storedState);
        }
    });
};



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

async function updateServerConfig(key, value) {
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
        configState.set(key, value);
        
    } catch (error) {
        console.error('Error updating configuration:', error);
    }
}
