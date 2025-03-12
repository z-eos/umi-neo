// Define the tree-item component using Vue 3 syntax
//import { defineComponent, ref, computed, reactive, createApp } from 'vue';
const { defineComponent, ref, computed, reactive, createApp } = Vue;

export const LdapTreeItem = defineComponent({
  name: 'LdapTreeItem',
  template: '#item-template',
  props: {
    item: Object
  },
  setup(props, { emit }) {
    const isOpen = ref(props.item.isOpen);

    const isFolder = computed(() => {
      return props.item.children && props.item.children.length;
    });

    const toggleItem = () => {
      if (isFolder.value) {
        props.item.isOpen = !props.item.isOpen;
      }
    };

    const setState = (branch, isOpenState) => {
      branch.isOpen = isOpenState;
      if (branch.children) {
        branch.children.forEach(item => setState(item, isOpenState));
      }
    };

    const toggleTree = () => {
      if (isFolder.value) {
        setState(props.item, !props.item.isOpen);
      }
    };

    // const makeFolder = () => {
    //   if (!isFolder.value) {
    //     // Using context.emit in Vue 3
    //     context.emit('make-folder', props.item);
    //     isOpen.value = true;
    //   }
    // };

    const makeFolder = () => {
      if (!isFolder.value) {
        // Using context.emit in Vue 3
        emit('make-folder', props.item);
        isOpen.value = true;
      }
    };

    const showItem = (scope) => {
      const url = scope ?
        '/search/common?no_layout=1&search_scope=sub&search_base_case=' + props.item.dn :
        '/search/common?no_layout=1&search_scope=base&search_base_case=' + props.item.dn;

      // Using fetch API
      fetch(url)
        .then(response => {
          if (!response.ok) {
            throw new Error('Network response was not ok');
          }
          return response.text();
        })
        .then(html => {
          document.getElementById('workingfield').innerHTML = html;
          
          // Scroll to the top of the page after loading the content
          window.scrollTo({
            top: 0,
            behavior: 'smooth'
          });
        })
        .catch(error => {
          console.warn('Fetch failed: ', error);
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

// Create the main application
// import { createApp } from 'vue';

const compareFunc = (a, b) => {
  const aVal = a.name.toLowerCase();
  const bVal = b.name.toLowerCase();
  if (aVal === bVal) return 0;
  return aVal > bVal ? 1 : -1;
};

const sortRecursively = arr => {
  if (arr.children) {
    arr.children = arr.children.map(sortRecursively).sort(compareFunc);
  }
  return arr;
};

// Boot up the Vue 3 app
const app = createApp({
  setup() {
    // State management with Vue 3 Composition API
    const loading = ref(false);
    let treeData;
    
    try {
      treeData = JSON.parse(localStorage.getItem('ldapTree'));
      if (!treeData) {
        treeData = {};
      }
    } catch {
      treeData = {};
    }
    
    const tree = ref(treeData);
    
    const makeFolder = (item) => {
      // Vue 3 way to set reactive properties
      item.children = [];
    };
    
    const getTreeData = async () => {
      console.warn('LDAP getTreeData called');
      loading.value = true;  // Start the loading spinner
      
      try {
        // Fetch the data from the server
        const response = await fetch('/tool/ldap-tree');
        
        // Check if the response is ok (status code 200–299)
        if (!response.ok) {
          throw new Error('LDAP Tree Network response was not ok');
        }
        
        // Parse the response as JSON
        const data = await response.json();
        
        // If data is valid, process it
        if (typeof data === 'object') {
          console.warn('LDAP Tree Data received: ', typeof data);
          // Process the data
          sortRecursively(data);
          // localStorage stuff
          localStorage.setItem('ldapTree', JSON.stringify(data));
          // Update the tree with the new data
          tree.value = data;
        } else {
          console.warn("LDAP Tree Received data is not in usable format: ", typeof data);
        }
      } catch (error) {
        // Handle any errors during the fetch operation
        console.warn('LDAP Tree Fetch request failed: ', error);
      } finally {
        // Stop loading spinner, whether the request succeeds or fails
        loading.value = false;
        console.warn('LDAP Tree Loading spinner stopped');
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

// In Vue 3, we need to register components before mounting
app.component('ldap-tree-item', LdapTreeItem);

// Mount the app to the element
app.mount('#ldap-tree');
