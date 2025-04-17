// Import Vue components from global Vue object
const { defineComponent, ref, computed, createApp } = Vue;

/**
 * Tree item component for displaying LDAP entries
 * Provides functionality for expanding/collapsing nodes and viewing LDAP data
 */
export const LdapTreeItem = defineComponent({
  name: 'LdapTreeItem',
  template: '#item-template',
  props: {
    item: {
      type: Object,
      required: true
    }
  },
  setup(props, { emit }) {
    // Track if the current item is open/expanded
    const isOpen = ref(props.item.isOpen);

    // Determine if item is a folder (has children)
    const isFolder = computed(() => 
      props.item.children && props.item.children.length > 0
    );

    /**
     * Toggle open/close state of current item
     */
    const toggleItem = () => {
      if (isFolder.value) {
        props.item.isOpen = !props.item.isOpen;
      }
    };

    /**
     * Recursively set open state for an item and all its children
     * @param {Object} branch - Branch to modify
     * @param {Boolean} isOpenState - State to set (true=open, false=closed)
     */
    const setState = (branch, isOpenState) => {
      branch.isOpen = isOpenState;
      if (branch.children) {
        branch.children.forEach(item => setState(item, isOpenState));
      }
    };

    /**
     * Toggle entire tree/subtree open or closed
     */
    const toggleTree = () => {
      if (isFolder.value) {
        setState(props.item, !props.item.isOpen);
      }
    };

    /**
     * Convert an item into a folder by adding children array
     */
    const makeFolder = () => {
      if (!isFolder.value) {
        emit('make-folder', props.item);
        isOpen.value = true;
      }
    };

    /**
     * Show the details of an LDAP item in the working field
     * @param {Boolean} scope - If true, show subtree; if false, show only this item
     */
    const showItem = (scope) => {
      // Build URL based on whether we want to show subtree or just this item
      const searchScope = scope ? 'sub' : 'base';
      const url = `/search/common?no_layout=1&search_scope=${searchScope}&search_base_case=${props.item.dn}`;

      // Fetch and display the LDAP entry
      fetch(url)
        .then(response => {
          if (!response.ok) {
            throw new Error(`Network response was not ok: ${response.status}`);
          }
          return response.text();
        })
        .then(html => {
          // scripts are ignored // document.getElementById('workingfield').innerHTML = html;
	  // jQuery must be used  
	  $('#workingfield').html(html)
	    
          // Smooth scroll to top of page
          window.scrollTo({
            top: 0,
            behavior: 'smooth'
          });
        })
        .catch(error => {
          console.error('Failed to fetch LDAP entry:', error);
        });
    };

    return {
      isOpen,
      isFolder,
      toggleItem,
      toggleTree,
      makeFolder,
      showItem,
      setState
    };
  }
});

/**
 * Compare function for sorting LDAP entries alphabetically (case-insensitive)
 */
const compareFunc = (a, b) => {
  const aVal = a.name.toLowerCase();
  const bVal = b.name.toLowerCase();
  return aVal === bVal ? 0 : (aVal > bVal ? 1 : -1);
};

/**
 * Sort an LDAP tree recursively
 * @param {Object} arr - The node to sort children of
 * @returns {Object} The sorted node
 */
const sortRecursively = node => {
  if (node.children && node.children.length > 0) {
    // Map and sort children recursively
    node.children = node.children.map(sortRecursively).sort(compareFunc);
  }
  return node;
};

// Create and configure the main Vue application
const app = createApp({
  setup() {
    // UI state tracking
    const loading = ref(false);
    
    // Try to load previously saved tree from localStorage
    let initialTreeData;
    try {
      initialTreeData = JSON.parse(localStorage.getItem('ldapTree')) || {};
    } catch (error) {
      console.warn('Failed to parse LDAP tree from localStorage:', error);
      initialTreeData = {};
    }
    
    // Reactive tree data
    const tree = ref(initialTreeData);
    
    /**
     * Convert an item into a folder by adding children array
     * @param {Object} item - Item to convert to folder
     */
    const makeFolder = (item) => {
      item.children = [];
    };
    
    /**
     * Fetch LDAP tree data from server
     * Updates tree state and saves to localStorage
     */
    const getTreeData = async () => {
      console.log('Fetching LDAP tree data...');
      loading.value = true;
      
      try {
        // Request tree data from server
        const response = await fetch('/tool/ldap-tree');
        
        if (!response.ok) {
          throw new Error(`LDAP Tree API error: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data && typeof data === 'object') {
          console.log('LDAP tree data received successfully');
          
          // Sort the data hierarchically
          sortRecursively(data);
          
          // Save to localStorage for future visits
          localStorage.setItem('ldapTree', JSON.stringify(data));
          
          // Update the UI
          tree.value = data;
        } else {
          console.error('Invalid LDAP tree data format:', typeof data);
        }
      } catch (error) {
        console.error('Failed to fetch LDAP tree data:', error);
      } finally {
        loading.value = false;
      }
    };
    
    return {
      tree,
      loading,
      makeFolder,
      getTreeData
    };
  }
});

// Register the tree item component
app.component('ldap-tree-item', LdapTreeItem);

// Mount the app to the DOM
app.mount('#ldap-tree');
