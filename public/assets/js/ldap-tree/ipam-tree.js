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
	showIpaItem: function (scope) {
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
		    console.debug('re match: url: '+url)
		} else {
		    url =
			'/search/common?no_layout=1' +
			'&search_base_case=search_global&search_filter=|'  +
			'(dhcpStatements=fixed-address ' + this.ipaitem.dn + '*)' +
			'(umiOvpnCfgIfconfigPush='       + this.ipaitem.dn + '*)' +
			'(umiOvpnCfgIroute='             + this.ipaitem.dn + '*)' +
			'(ipHostNumber='                 + this.ipaitem.dn + '*)' +
			'&search_scope=sub';
		    console.debug('re do not match: url: '+url)
		}
		$.ajax({
		    url: url,
		    success: function (html) {
			$('#workingfield').html(html);
			// handleResponce();
		    }
		});
	    } else {
		url = '/tool/ipa-tree?naddr=' + this.ipaitem.dn;
		$.ajax({
		    url: url,
		    success: function(faddr) {
			if (typeof faddr === 'string') {
			    // console.log('faddr is string')
			    faddr = JSON.parse(faddr)
			} else if (typeof faddr === 'object') {
			    console.log('faddr is object')
			    faddr = faddr.json_tree
			} else {
			    console.error("Data has unusable format - ", typeof faddr)
			    return
			}
			sortIpaRecursively(faddr);
			_this.faddr = faddr;
			// console.log(faddr)
		    }
		});
	    }
	},
	resolveThis: function () {
	    var item = this.ipaitem;
	    // console.log(item.isOpen);
	    if ( item.host || item.dn.split(".").length < 4 ) {
		return;
	    }
	    var url = '/tool/resolve?ptr=' + item.dn;
	    $.ajax({
		url: url,
		success: function (host) {
		    // if ( host.indexOf('<') == -1) {
		    // 	item.host = host;
		    // } else {
		    // 	item.host = 'NXDOMAIN';
		    // }
		    item.host = host;
		    // console.log(host);
		}
	    });
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
