// Vue 3 IPAM Tree Component
const { ref, computed, reactive, createApp } = Vue;

// Define the tree-item component
export const IpamTreeItem = {
  template: '#ipam-template',
  props: {
    ipaitem: Object,
    faddr: Object
  },
    setup(props, { emit } ) {
    const isOpen = ref(props.ipaitem && props.ipaitem.isOpen);
    const isOpenFaddr = ref(false);
    
    const isIpaFolder = computed(() => {
      return props.ipaitem && props.ipaitem.children && props.ipaitem.children.length;
    });

    const toggleIpaItem = () => {
      if (isIpaFolder.value) {
        props.ipaitem.isOpen = !props.ipaitem.isOpen;
      }
    };

    const setIpaState = (branch, isOpenState) => {
      if (branch.children) {
        branch.isOpen = isOpenState;
        branch.children.forEach(ipaitem => setIpaState(ipaitem, isOpenState));
      }
    };

    const toggleIpaTree = () => {
      if (isIpaFolder.value) {
        setIpaState(props.ipaitem, !props.ipaitem.isOpen);
      }
    };

    const makeIpaFolder = (event) => {
      if (!isIpaFolder.value) {
        event.target.dispatchEvent(new CustomEvent('make-folder', {
          bubbles: true, 
          detail: { ipaitem: props.ipaitem }
        }));
        isOpen.value = true;
      }
    };

    const copyText = (event) => {
      const textNode = event.target;
      const range = document.createRange();
      range.selectNodeContents(textNode);

      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);

      document.getElementById('ip-copied').innerHTML = event.target.innerText;
      document.getElementById('ip-copied-toast').dispatchEvent(new CustomEvent('show'));

      document.execCommand('copy');
      selection.removeAllRanges();
    };

    const showIpaItem = async (scope) => {
      let url;
      const re = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){3}$/;
      let ip;
      
      if (!re.test(props.ipaitem.dn) || (re.test(props.ipaitem.dn) && scope)) {
        const ipv4Re = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;
        
        if (ipv4Re.test(props.ipaitem.dn)) {
          url = '/search/common?no_layout=1' +
            '&search_base_case=search_global&search_filter=|' +
            '(dhcpStatements=fixed-address ' + props.ipaitem.dn + ')' +
            '(umiOvpnCfgIfconfigPush=' + props.ipaitem.dn + '*)' +
            '(umiOvpnCfgIroute=' + props.ipaitem.dn + '*)' +
            '(ipHostNumber=' + props.ipaitem.dn + ')' +
            '&search_scope=sub';
          console.debug('IPAM: re match: url: ' + url);
        } else {
          url = '/search/common?no_layout=1' +
            '&search_base_case=search_global&search_filter=|' +
            '(dhcpStatements=fixed-address ' + props.ipaitem.dn + '*)' +
            '(umiOvpnCfgIfconfigPush=' + props.ipaitem.dn + '*)' +
            '(umiOvpnCfgIroute=' + props.ipaitem.dn + '*)' +
            '(ipHostNumber=' + props.ipaitem.dn + '*)' +
            '&search_scope=sub';
          console.debug('IPAM: re do not match: url: ' + url);
        }
        
        try {
          const response = await fetch(url);
          const html = await response.text();
          document.getElementById('workingfield').innerHTML = html;
        } catch (error) {
          console.error('IPAM: Error fetching data:', error);
        }
      } else {
        url = '/tool/ipa-tree?naddr=' + props.ipaitem.dn;
        console.log(url);
        
        try {
          const response = await fetch(url);
          let faddrData = await response.json();

          if (typeof faddrData === 'object') {
            console.log('IPAM: faddr is object');
            sortIpaRecursively(faddrData);
            // In Vue 3, we need to emit an event to update parent component's state
            event.target.dispatchEvent(new CustomEvent('update-faddr', {
              bubbles: true,
              detail: { faddr: faddrData }
            }));
          } else {
            console.error('IPAM: Data has unusable format:', typeof faddrData);
            return;
          }
        } catch (error) {
          console.error('IPAM: Error fetching faddr:', error);
        }
      }
    };

    const resolveThis = async () => {
      const item = props.ipaitem;
      
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

    return {
      isOpen,
      isOpenFaddr,
      isIpaFolder,
      toggleIpaItem,
      toggleIpaTree,
      makeIpaFolder,
      copyText,
      showIpaItem,
      resolveThis,
      setIpaState
    };
  }
};

// Main application

// Utility functions
function inet_aton(ip) {
  // split into octets
  const a = ip.split('.');
  const buffer = new ArrayBuffer(4);
  const dv = new DataView(buffer);
  for (let i = 0; i < 4; i++) {
    dv.setUint8(i, a[i]);
  }
  return dv.getUint32(0);
}

const compareIpaFunc = (a, b) => {
  const aVal = a.name.toLowerCase();
  const bVal = b.name.toLowerCase();
  if (aVal === bVal) return 0;
  return inet_aton(aVal) > inet_aton(bVal) ? 1 : -1;
};

const sortIpaRecursively = arr => {
  if (arr.children) {
    arr.children = arr.children.map(sortIpaRecursively).sort(compareIpaFunc);
  }
  return arr;
};

// Create app
const app = createApp({
  components: {
    'ipam-tree-item': IpamTreeItem
  },
  setup() {
    let ipamtree = reactive({});
    const loading = ref(false);

    try {
      const storedTree = JSON.parse(localStorage.getItem('ipamTree'));
      if (storedTree) {
        ipamtree = reactive(storedTree);
      }
    } catch {
      // Keep default empty object
    }

    // Event handlers
    const makeIpaFolder = (event) => {
      const { ipaitem } = event.detail;
      if (!ipaitem.children) {
        ipaitem.children = [];
      }
    };

    const updateFaddr = (event) => {
      const { faddr } = event.detail;
      // Update your data model as needed
    };

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
          
          // Update reactive data
          Object.assign(ipamtree, data);
          loading.value = false;
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

    // Event listeners
    document.addEventListener('make-folder', makeIpaFolder);
    document.addEventListener('update-faddr', updateFaddr);

    return {
      ipamtree,
      loading,
      makeIpaFolder,
      getIpaTreeData
    };
  }
});

// Mount app to element
app.mount('#ipam-tree');
