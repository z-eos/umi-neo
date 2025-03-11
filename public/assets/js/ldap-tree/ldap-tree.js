// define the tree-item component
Vue.component('ldap-tree-item', {
  template: '#item-template',
  props: {
    item: Object
  },
  data: function () {
    return { isOpen: this.item.isOpen }
  },
  computed: {
    isFolder: function () {
      return this.item.children && this.item.children.length
    }
  },
  methods: {
    toggleItem: function () {
      if (this.isFolder) {
	this.item.isOpen = !this.item.isOpen
      }
    },
    setState: function (branch, isOpen) {
      var self = this;
      branch.isOpen = isOpen;
      if ( branch.children ) {
	branch.children.forEach( function(item) {self.setState(item, isOpen)} )
      }
    },
    toggleTree: function () {
      //debugger;
      if (this.isFolder) {
	this.setState(this.item, !this.item.isOpen)
      }
    },
    makeFolder: function () {
      if (!this.isFolder) {
      	this.$emit('make-folder', this.item)
	this.isOpen = true
      }
    },
    showItem: function (scope) {
      // console.log(this.item.dn);
      var url = scope ?
	  '/search/common?no_layout=1&search_scope=sub&search_base_case='  + this.item.dn :
	  '/search/common?no_layout=1&search_scope=base&search_base_case=' + this.item.dn;

      // $.ajax({
      // 	url: url,
      // 	success: function (html) {
      // 	    $('#workingfield').html(html);
      // 	    handleResponce();
      // 	}
      // });

      // Use the native fetch API to make an HTTP request
      fetch(url)
	.then(response => {
	  // Ensure the response is OK (status code 200–299)
	  if (!response.ok) {
	    throw new Error('Network response was not ok');
	  }
	  // Parse the response as text (since you are inserting it as HTML)
	  return response.text();
	})
	.then(html => {
	  // Insert the received HTML into the #workingfield element
	  document.getElementById('workingfield').innerHTML = html;
	  //handleResponce();  // Call the function to handle the response
	  
	  // Scroll to the top of the page after loading the content
	  window.scrollTo({
	    top: 0,
	    behavior: 'smooth' // Optional: Adds a smooth scrolling effect
          });
	})
	.catch(error => {
	  console.warn('Fetch failed: ', error);  // Log any errors
	});




      
      // console.log('showItem scope:', scope);
    }
  }
});


// boot up
var ldapTree = new Vue({
  el: '#ldap-tree',

  data: function () {
    let tree;
    try {
      tree = JSON.parse(localStorage.getItem('ldapTree'));
      if ( ! tree ) {
	tree = {};
      }
    } catch {
      tree = {};
    }
    return { tree: tree,
	     loading: false }
  },

  mounted: function () {
    // this.getTreeData();
  },
  
  methods: {
    makeFolder: function (item) {
      Vue.set(item, 'children', [])
    },

    getTreeData: async function () {
      console.warn('LDAP getTreeData called');
      var _this = this;
      _this.loading = true;  // Start the loading spinner

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
	  // Assuming a function to process the data
	  sortRecursively(data);
	  // localStorage stuff
	  localStorage.setItem('ldapTree', JSON.stringify(data));
	  // Update the tree with the new data
	  _this.tree = data;
	} else {
	  console.warn("LDAP Tree Received data is not in usable format: ", typeof data);
	}
      } catch (error) {
	// Handle any errors during the fetch operation
	console.warn('LDAP Tree Fetch request failed: ', error);
      } finally {
	// Stop loading spinner, whether the request succeeds or fails
	_this.loading = false;
	console.warn('LDAP Tree Loading spinner stopped');
      }
    }
  }
});


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
