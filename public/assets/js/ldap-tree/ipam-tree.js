// define the tree-item component
Vue.component('ipam-tree-item', {
    template: '#ipam-template',
    props: {
	ipaitem: Object,
	faddr: Object
    },
    data: function () {
	return { isOpen: this.ipaitem && this.ipaitem.isOpen,
	         isOpenFaddr: false }
    },
    computed: {
	isIpaFolder: function () {
	    return this.ipaitem && this.ipaitem.children && this.ipaitem.children.length
	}
    },
    methods: {
	toggleIpaItem: function () {
	    if (this.isIpaFolder) {
		this.ipaitem.isOpen = !this.ipaitem.isOpen
	    }
	},
	setIpaState: function (branch, isOpen) {
	    var self = this;
	    if ( branch.children ) {
		branch.isOpen = isOpen;
		branch.children.forEach( function(ipaitem) {self.setIpaState(ipaitem, isOpen)} )
	    }
	},
	toggleIpaTree: function () {
	    //debugger;
	    if (this.isIpaFolder) {
		this.setIpaState(this.ipaitem, !this.ipaitem.isOpen)
	    }
	},
	makeIpaFolder: function () {
	    if (!this.isIpaFolder) {
      		this.$emit('make-folder', this.ipaitem)
		this.isOpen = true
	    }
	},
	showIpaItem: async function (scope) {
	    // console.log(this.ipaitem.dn);
	    var url;
	    var re    = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){3}$/;
	    var _this = this;
	    var ip; 
	    if ( !re.test(this.ipaitem.dn) || (re.test(this.ipaitem.dn) && scope) ) {
		re = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;
		if ( re.test(this.ipaitem.dn) ) {
		    url =
			'/search/common?no_layout=1' +
			'&search_base_case=search_global&search_filter=|'  +
			'(dhcpStatements=fixed-address ' + this.ipaitem.dn + ')'  +
			'(umiOvpnCfgIfconfigPush='       + this.ipaitem.dn + '*)' +
			'(umiOvpnCfgIroute='             + this.ipaitem.dn + '*)' +
			'(ipHostNumber='                 + this.ipaitem.dn + ')'  +
			'&search_scope=sub';
		    console.debug('IPAM: re match: url: '+url)
		} else {
		    url =
			'/search/common?no_layout=1' +
			'&search_base_case=search_global&search_filter=|'  +
			'(dhcpStatements=fixed-address ' + this.ipaitem.dn + '*)' +
			'(umiOvpnCfgIfconfigPush='       + this.ipaitem.dn + '*)' +
			'(umiOvpnCfgIroute='             + this.ipaitem.dn + '*)' +
			'(ipHostNumber='                 + this.ipaitem.dn + '*)' +
			'&search_scope=sub';
		    console.debug('IPAM: re do not match: url: '+url)
		}
		try {
		    const response = await fetch(url); // Make the HTTP request
		    const html = await response.text(); // Await the HTML response
		    document.getElementById('workingfield').innerHTML = html; // Inject the HTML
		    // handleResponce(); // Uncomment if you have this function
		} catch (error) {
		    console.error('IPAM: Error fetching data:', error); // Error handling
		}
	    } else {
		url = '/tool/ipa-tree?naddr=' + this.ipaitem.dn;
		console.log(url)
		try {
		    const response = await fetch(url); // Make the HTTP request
		    let faddr = await response.json(); // Await JSON response

		    if (typeof faddr === 'object') {
			console.log('IPAM: faddr is object');
			// faddr = faddr.json_tree;
			sortIpaRecursively(faddr); // Assuming this is defined elsewhere
			_this.faddr = faddr; // Set the component's `faddr` data
		    } else {
			console.error('IPAM: Data has unusable format:', typeof faddr);
			return;
		    }
		} catch (error) {
		    console.error('IPAM: Error fetching faddr:', error); // Error handling
		}
	    }
	},
	resolveThis: async function () {
	    var item = this.ipaitem;
	    // console.log(item.isOpen);
	    if ( item.host || item.dn.split(".").length < 4 ) {
		return;
	    }
	    var url = '/tool/resolve?ptr=' + item.dn;
	    try {
		const response = await fetch(url); // Make the HTTP request
		const host = await response.text(); // Await the host name
		item.host = host; // Set the resolved host
		// console.log(host);
	    } catch (error) {
		console.error('IPAM: Error resolving item:', error); // Error handling
	    }
	    // console.log('showItem scope:', scope);
	}
    }
});


// boot up
var ipamTree = new Vue({
    el: '#ipam-tree',

    data: function () {
        return { ipamtree: {},
		 loading: false }
    },
    
    mounted: function () {
        // this.getIpaTreeData();
    },

    methods: {
	makeIpaFolder: function (ipaitem) {
    	    Vue.set(ipaitem, 'children', [])
	},
	
	getIpaTreeData: async function () {
	    var _this = this;
	    _this.loading = true;

	    try {
		// Fetch the data from the server
		const response = await fetch('/tool/ipa-tree');

		// Check if the response is ok (status code 200–299)
		if (!response.ok) {
		    throw new Error('IPA Network response was not ok');
		}

		// Parse the response as JSON
		const data = await response.json();

		// If data is valid, process it
		if (typeof data === 'object') {
		    console.debug('IPA Data received: ', typeof data);
		    // Assuming a function to process the data
		    sortIpaRecursively(data);
		    // Update the tree with the new data
		    _this.ipamtree = data;
		    _this.hover = false;
		    _this.loading = false;
		} else {
		    console.error("IPA Received data is not in usable format: ", typeof data);
		}
	    } catch (error) {
		// Handle any errors during the fetch operation
		console.error('IPA Fetch request failed: ', error);
	    } finally {
		// Stop loading spinner, whether the request succeeds or fails
		_this.loading = false;
		console.debug('IPA Loading spinner stopped');
	    }
	},
      copyText: function (text) {
	navigator.clipboard.writeText(text);
      }
    }
});

function inet_aton(ip){
    // split into octets
    var a = ip.split('.');
    var buffer = new ArrayBuffer(4);
    var dv = new DataView(buffer);
    for(var i = 0; i < 4; i++){
        dv.setUint8(i, a[i]);
    }
    return(dv.getUint32(0));
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

/*
// function for copying selected text in clipboard
function copyText() {
    selectText();

    $('#ip-copied').html(event.target.innerText)
    $('#ip-copied-toast').toast('show')
    // $(event.target).popover({ container: $(event.target).parent(),
    // 			      content: event.target.innerText + ' copied to clipboard' })
    
    //alert(event.target.innerText + ' copied to clipboard')
    document.execCommand("copy");
}

function selectText() {
    var element = event.target
    var range;
    if (document.selection) {
        // IE
        range = document.body.createTextRange();
        range.moveToElementText(element);
        range.select();
    } else if (window.getSelection) {
        range = document.createRange();
        range.selectNode(element);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
    }
}
*/

/* v3 */
// import { createApp, reactive, ref } from 'vue';

// // define the tree-item component
// const IpamTreeItem = {
//     template: '#ipam-template',
//     props: {
//         ipaitem: Object,
//         faddr: Object
//     },
//     setup(props, { emit }) {
//         const isOpen = ref(props.ipaitem && props.ipaitem.isOpen);
//         const isOpenFaddr = ref(false);

//         const isIpaFolder = computed(() => {
//             return props.ipaitem && props.ipaitem.children && props.ipaitem.children.length;
//         });

//         const toggleIpaItem = () => {
//             if (isIpaFolder.value) {
//                 props.ipaitem.isOpen = !props.ipaitem.isOpen;
//             }
//         };

//         const setIpaState = (branch, isOpen) => {
//             if (branch.children) {
//                 branch.isOpen = isOpen;
//                 branch.children.forEach(child => setIpaState(child, isOpen));
//             }
//         };

//         const toggleIpaTree = () => {
//             if (isIpaFolder.value) {
//                 setIpaState(props.ipaitem, !props.ipaitem.isOpen);
//             }
//         };

//         const makeIpaFolder = () => {
//             if (!isIpaFolder.value) {
//                 emit('make-folder', props.ipaitem);
//                 isOpen.value = true;
//             }
//         };

//         const showIpaItem = async (scope) => {
//             let url;
//             const re = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){3}$/;
//             const _this = this;
//             if (!re.test(props.ipaitem.dn) || (re.test(props.ipaitem.dn) && scope)) {
//                 const re2 = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;
//                 if (re2.test(props.ipaitem.dn)) {
//                     url =
//                         '/search/common?no_layout=1' +
//                         '&search_base_case=search_global&search_filter=|' +
//                         '(dhcpStatements=fixed-address ' + props.ipaitem.dn + ')' +
//                         '(umiOvpnCfgIfconfigPush=' + props.ipaitem.dn + '*)' +
//                         '(umiOvpnCfgIroute=' + props.ipaitem.dn + '*)' +
//                         '(ipHostNumber=' + props.ipaitem.dn + ')' +
//                         '&search_scope=sub';
//                     console.debug('IPAM: re match: url: ' + url);
//                 } else {
//                     url =
//                         '/search/common?no_layout=1' +
//                         '&search_base_case=search_global&search_filter=|' +
//                         '(dhcpStatements=fixed-address ' + props.ipaitem.dn + '*)' +
//                         '(umiOvpnCfgIfconfigPush=' + props.ipaitem.dn + '*)' +
//                         '(umiOvpnCfgIroute=' + props.ipaitem.dn + '*)' +
//                         '(ipHostNumber=' + props.ipaitem.dn + '*)' +
//                         '&search_scope=sub';
//                     console.debug('IPAM: re do not match: url: ' + url);
//                 }
//                 try {
//                     const response = await fetch(url);
//                     const html = await response.text();
//                     document.getElementById('workingfield').innerHTML = html;
//                 } catch (error) {
//                     console.error('IPAM: Error fetching data:', error);
//                 }
//             } else {
//                 url = '/tool/ipa-tree?naddr=' + props.ipaitem.dn;
//                 console.log(url);
//                 try {
//                     const response = await fetch(url);
//                     const faddr = await response.json();

//                     if (typeof faddr === 'object') {
//                         console.log('IPAM: faddr is object');
//                         sortIpaRecursively(faddr);
//                         props.faddr = faddr;
//                     } else {
//                         console.error('IPAM: Data has unusable format:', typeof faddr);
//                         return;
//                     }
//                 } catch (error) {
//                     console.error('IPAM: Error fetching faddr:', error);
//                 }
//             }
//         };

//         const resolveThis = async () => {
//             const item = props.ipaitem;
//             if (item.host || item.dn.split('.').length < 4) {
//                 return;
//             }
//             const url = '/tool/resolve?ptr=' + item.dn;
//             try {
//                 const response = await fetch(url);
//                 const host = await response.text();
//                 item.host = host;
//             } catch (error) {
//                 console.error('IPAM: Error resolving item:', error);
//             }
//         };

//         return {
//             isOpen,
//             isOpenFaddr,
//             isIpaFolder,
//             toggleIpaItem,
//             setIpaState,
//             toggleIpaTree,
//             makeIpaFolder,
//             showIpaItem,
//             resolveThis
//         };
//     }
// };

// // Main app initialization
// const app = createApp({
//     setup() {
//         const ipamtree = reactive({});
//         const loading = ref(false);

//         const makeIpaFolder = (ipaitem) => {
//             ipaitem.children = reactive([]);
//         };

//         const getIpaTreeData = async () => {
//             loading.value = true;
//             try {
//                 const response = await fetch('/tool/ipa-tree');
//                 if (!response.ok) {
//                     throw new Error('IPA Network response was not ok');
//                 }
//                 const data = await response.json();
//                 if (typeof data === 'object') {
//                     console.debug('IPA Data received: ', typeof data);
//                     sortIpaRecursively(data);
//                     ipamtree.value = data;
//                 } else {
//                     console.error('IPA Received data is not in usable format: ', typeof data);
//                 }
//             } catch (error) {
//                 console.error('IPA Fetch request failed: ', error);
//             } finally {
//                 loading.value = false;
//                 console.debug('IPA Loading spinner stopped');
//             }
//         };

//         return {
//             ipamtree,
//             loading,
//             makeIpaFolder,
//             getIpaTreeData
//         };
//     }
// });

// app.component('ipam-tree-item', IpamTreeItem);

// app.mount('#ipam-tree');

// // Utility functions
// function inet_aton(ip) {
//     const a = ip.split('.');
//     const buffer = new ArrayBuffer(4);
//     const dv = new DataView(buffer);
//     for (let i = 0; i < 4; i++) {
//         dv.setUint8(i, a[i]);
//     }
//     return dv.getUint32(0);
// }

// const compareIpaFunc = (a, b) => {
//     const aVal = a.name.toLowerCase();
//     const bVal = b.name.toLowerCase();
//     if (aVal === bVal) return 0;
//     return inet_aton(aVal) > inet_aton(bVal) ? 1 : -1;
// };

// const sortIpaRecursively = (arr) => {
//     if (arr.children) {
//         arr.children = arr.children.map(sortIpaRecursively).sort(compareIpaFunc);
//     }
//     return arr;
// };

// // function for copying selected text in clipboard
// function copyText() {
//     selectText();
//     $('#ip-copied').html(event.target.innerText);
//     $('#ip-copied-toast').toast('show');
//     document.execCommand("copy");
// }

// function selectText() {
//     const element = event.target;
//     const range = document.createRange();
//     range.selectNode(element);
//     window.getSelection().removeAllRanges();
//     window.getSelection().addRange(range);
// }
