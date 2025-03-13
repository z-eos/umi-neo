/**
 * Vue 3 IPAM Tree Component
 * 
 * This file creates a tree view component for IP Address Management.
 * It allows users to browse IP addresses and networks in a hierarchical tree structure,
 * with features for expanding/collapsing nodes, copying IP addresses, and resolving hostnames.
 */

// Import required Vue 3 functionality
const { ref, computed, reactive, createApp } = Vue;

// Define the tree-item component - This is the recursive component for each node in the tree
export const IpamTreeItem = {
    // Template reference - Refers to an HTML template with id='ipam-template' defined elsewhere
    template: '#ipam-template',
    
    // Component props - Receives an ipaitem object that contains IP node data
    props: {
        ipaitem: Object
    },
    
    // Events emitted by this component
    emits: ['make-folder', 'show-toast'],
    
    // Component setup function with props and context
    setup(props, { emit }) {
        // Reactive state variables
        const isOpen = ref(props.ipaitem && props.ipaitem.isOpen); // Tracks if the tree node is expanded
        const isOpenFaddr = ref(false); // Tracks if address details are shown
        const faddr = ref(null); // Stores fetched address details
        
        // Computed property to determine if the node is a folder (has children)
        const isIpaFolder = computed(() => {
            return props.ipaitem && props.ipaitem.children && props.ipaitem.children.length;
        });

        /**
         * Toggle open/close state of the current node
         */
        const toggleIpaItem = () => {
            if (isIpaFolder.value) {
                props.ipaitem.isOpen = !props.ipaitem.isOpen;
            }
        };

        /**
         * Recursively set the open state for all children of a branch
         * @param {Object} branch - The branch node to update
         * @param {Boolean} isOpenState - Whether nodes should be open or closed
         */
        const setIpaState = (branch, isOpenState) => {
            if (branch.children) {
                branch.isOpen = isOpenState;
                branch.children.forEach(ipaitem => setIpaState(ipaitem, isOpenState));
            }
        };

        /**
         * Toggle the entire tree branch open or closed
         */
        const toggleIpaTree = () => {
            if (isIpaFolder.value) {
                setIpaState(props.ipaitem, !props.ipaitem.isOpen);
            }
        };

        /**
         * Convert a regular node to a folder node
         */
        const makeIpaFolder = () => {
            if (!isIpaFolder.value) {
                emit('make-folder', { ipaitem: props.ipaitem });
                isOpen.value = true;
            }
        };

        /**
         * Copy IP address to clipboard when clicked
         * @param {Event} event - The click event
         */
        const copyText = (event) => {
            // Create a text selection on the clicked element
            const textNode = event.target;
            const range = document.createRange();
            range.selectNodeContents(textNode);

            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);

            // Update the copied text display
            document.getElementById('ip-copied').innerHTML = event.target.innerText;
            
            // Show toast notification that text was copied
            emit('show-toast');

            // Execute the copy command and clean up selection
            document.execCommand('copy');
            selection.removeAllRanges();
        };
        
        /**
         * Show details for the IP address - fetches related data from server
         * @param {String} scope - Optional scope parameter for the search
         */
        const showIpaItem = async (scope) => {
            let url;
            // Regular expression to validate IPv4 address (first 3 octets)
            const re = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){3}$/;
            
            if (!re.test(props.ipaitem.dn) || (re.test(props.ipaitem.dn) && scope)) {
                // Regular expression for complete IPv4 address (all 4 octets)
                const ipv4Re = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;
                
                // Different search queries based on whether it's a complete IP or partial network
                if (ipv4Re.test(props.ipaitem.dn)) {
                    // For complete IP addresses - search for exact matches
                    url = '/search/common?no_layout=1' +
                        '&search_base_case=search_global&search_filter=|' +
                        '(dhcpStatements=fixed-address ' + props.ipaitem.dn + ')' +
                        '(umiOvpnCfgIfconfigPush=' + props.ipaitem.dn + '*)' +
                        '(umiOvpnCfgIroute=' + props.ipaitem.dn + '*)' +
                        '(ipHostNumber=' + props.ipaitem.dn + ')' +
                        '&search_scope=sub';
                    console.debug('IPAM: re match: url: ' + url);
                } else {
                    // For network addresses - search for patterns starting with this network
                    url = '/search/common?no_layout=1' +
                        '&search_base_case=search_global&search_filter=|' +
                        '(dhcpStatements=fixed-address ' + props.ipaitem.dn + '*)' +
                        '(umiOvpnCfgIfconfigPush=' + props.ipaitem.dn + '*)' +
                        '(umiOvpnCfgIroute=' + props.ipaitem.dn + '*)' +
                        '(ipHostNumber=' + props.ipaitem.dn + '*)' +
                        '&search_scope=sub';
                    console.debug('IPAM: re do not match: url: ' + url);
                }
                
                // Fetch and display search results
                try {
                    const response = await fetch(url);
                    const html = await response.text();
                    document.getElementById('workingfield').innerHTML = html;
                } catch (error) {
                    console.error('IPAM: Error fetching data:', error);
                }
            } else {
                // For network addresses - get subnet information
                url = '/tool/ipa-tree?naddr=' + props.ipaitem.dn;
                console.log(url);
                
                try {
                    const response = await fetch(url);
                    let faddrData = await response.json();

                    if (typeof faddrData === 'object') {
                        console.log('IPAM: faddr is object');
                        sortIpaRecursively(faddrData);
                        // Update local faddr
                        faddr.value = faddrData;
                    } else {
                        console.error('IPAM: Data has unusable format:', typeof faddrData);
                        return;
                    }
                } catch (error) {
                    console.error('IPAM: Error fetching faddr:', error);
                }
            }
        };

        /**
         * Resolve IP address to hostname using reverse DNS lookup
         */
        const resolveThis = async () => {
            const item = props.ipaitem;
            
            // Skip if already has a hostname or isn't a complete IP address
            if (item.host || item.dn.split(".").length < 4) {
                return;
            }
            
            const url = '/tool/resolve?ptr=' + item.dn;
            
            try {
                const response = await fetch(url);
                const host = await response.text();
                item.host = host;
            } catch (error) {
                console.error('IPAM: Error resolving item:', error);
            }
        };

        // Return all methods and properties needed by the template
        return {
            copyText,
            faddr,
            isIpaFolder,
            isOpen,
            isOpenFaddr,
            makeIpaFolder,
            resolveThis,
            setIpaState,
            showIpaItem,
            toggleIpaItem,
            toggleIpaTree,
        };
    }
};

// Utility functions for IP address sorting and handling

/**
 * Convert an IP address to a numeric value for comparison
 * @param {String} ip - IP address in dotted decimal notation
 * @returns {Number} - Numeric representation of the IP address
 */
function inet_aton(ip) {
    const a = ip.split('.');
    const buffer = new ArrayBuffer(4);
    const dv = new DataView(buffer);
    for (let i = 0; i < 4; i++) {
        dv.setUint8(i, a[i]);
    }
    return dv.getUint32(0);
}

/**
 * Comparison function for sorting IP addresses
 * @param {Object} a - First IP node to compare
 * @param {Object} b - Second IP node to compare
 * @returns {Number} - Comparison result (-1, 0, or 1)
 */
const compareIpaFunc = (a, b) => {
    const aVal = a.name.toLowerCase();
    const bVal = b.name.toLowerCase();
    if (aVal === bVal) return 0;
    return inet_aton(aVal) > inet_aton(bVal) ? 1 : -1;
};

/**
 * Recursively sort the IP tree by numeric IP value
 * @param {Object} arr - Tree node to sort
 * @returns {Object} - Sorted tree node
 */
const sortIpaRecursively = arr => {
    if (arr.children) {
        arr.children = arr.children.map(sortIpaRecursively).sort(compareIpaFunc);
    }
    return arr;
};

// Create the main Vue application
const app = createApp({
    setup() {
        // Application state variables
        const loading = ref(false); // Tracks loading state during data fetching
        const toastInstance = ref(null); // Stores Bootstrap toast component instance

        // Try to load saved tree data from localStorage
        let tree;
        try {
            tree = JSON.parse(localStorage.getItem('ipamTree'));
            if (!tree) {
                tree = {};
            }
        } catch {
            tree = {};
        }

        // Reactive reference to the tree data
        const ipamtree = ref(tree);

        /**
         * Initialize Bootstrap toast after component is mounted
         */
        const initToast = () => {
            const toastEl = document.getElementById('ip-copied-toast');
            if (toastEl) {
                toastInstance.value = new bootstrap.Toast(toastEl);
            }
        };

        // Event handlers for the tree components
        
        /**
         * Handler for 'make-folder' event - converts node to a folder
         * @param {Object} event - Event object containing the node to convert
         */
        const makeIpaFolder = (event) => {
            const { ipaitem } = event;
            if (!ipaitem.children) {
                ipaitem.children = [];
            }
        };

        /**
         * Handler to show the "IP copied" toast notification
         */
        const showToast = () => {
            if (toastInstance.value) {
                toastInstance.value.show();
            }
        };

        /**
         * Fetch the IP tree data from the server
         */
        const getIpaTreeData = async () => {
            loading.value = true;

            try {
                const response = await fetch('/tool/ipa-tree');

                if (!response.ok) {
                    throw new Error('IPA Network response was not ok');
                }

                const data = await response.json();

                if (typeof data === 'object') {
                    console.debug('IPA Data received: ', typeof data);
                    sortIpaRecursively(data);
                    localStorage.setItem('ipamTree', JSON.stringify(data));
                    
                    ipamtree.value = data;
                } else {
                    console.error("IPA Received data is not in usable format: ", typeof data);
                }
            } catch (error) {
                console.error('IPA Fetch request failed: ', error);
            } finally {
                loading.value = false;
                console.debug('IPA Loading spinner stopped');
            }
        };

        // Return all methods and properties needed by the template
        return {
            getIpaTreeData,
            initToast,
            ipamtree,
            loading,
            makeIpaFolder,
            showToast
        };
    },
    
    // Lifecycle hook - called after component is mounted to DOM
    mounted() {
        this.initToast();
    }
});

// Register the tree item component
app.component('ipam-tree-item', IpamTreeItem);

// Mount the application to the element with id 'ipam-tree'
app.mount('#ipam-tree');
