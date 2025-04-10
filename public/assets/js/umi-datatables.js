const reqPath = window.location.pathname;
const timestamp = new Date().toISOString().replace(/[-T:Z]/g, '').slice(0, 14);
const pathStrip = reqPath.replace(/^\/|\/$/g, '').replace(/\//g, '-');
const fileName = `${pathStrip}-${timestamp}`;

function customBodyFormatter(data, row, column, node) {
  let text = data;
  if (node instanceof HTMLElement) {
    const icon = node.querySelector('i');
    if (icon && icon.getAttribute('title')) {
      text = icon.getAttribute('title');
    } else {
      text = $(node).text();
    }
  }
  // Remove newlines and collapse multiple whitespace characters into one
  return text.replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ').trim();
}

var table = $('#dataTableToDraw').DataTable({
    dom: "<'h6 col-12'i><'row'<'col m-0 p-0 btn-group'B><'col align-self-end'f>>" +
	"rt" + "<'row'<'col m-0 p-0'l><'col d-flex justify-content-end m-0 p-0'p>>",
    buttons: [
	{
	    extend: 'copyHtml5',
	    text: '<i title="Copy current page data to clipboard" class="fa-regular fa-copy fa-lg fa-fw"></i>',
	    className: 'btn btn-primary btn-sm',
	    exportOptions: {
		format: {
		    body: customBodyFormatter
		},
		modifier: {
		    page: 'current'
		}
	    }
	},
	{
	    extend: 'print',
	    text: '<i title="Print current page" class="fa-solid fa-print fa-lg fa-fw"></i>',
	    className: 'btn btn-primary btn-sm',
	    autoPrint: false,
	    exportOptions: {
		format: {
		    body: function ( data, row, column, node ) {
			// If the cell contains an icon with a title attribute, return that title.
			// Assuming the icon is an <i> element.
			if ( node instanceof HTMLElement ) {
			    // Try to find an <i> element inside the node and get its title
			    const icon = node.querySelector('i');
			    if ( icon && icon.getAttribute('title') ) {
				return icon.getAttribute('title');
			    }
			}
			// Otherwise, return the plain data
			return data;
		    }
		},
		modifier: {
		    page: 'current'
		}
	    },
	    filename: fileName,
	    orientation: 'landscape'
	},
	{
	    extend: 'csvHtml5',
	    text: '<i title="Download current page as CSV file" class="fa-solid fa-file-csv fa-lg fa-fw"></i>',
	    className: 'btn btn-primary btn-sm',
	    exportOptions: {
		format: {
		    body: customBodyFormatter
		},
		modifier: {
		    page: 'current'
		}
	    },
	    filename: fileName
	},
	{
	    extend: 'excelHtml5',
	    text: '<i title="Download current page as EXCEL file" class="fa-regular fa-file-excel fa-lg fa-fw"></i>',
	    className: 'btn btn-primary btn-sm',
	    exportOptions: {
		format: {
		    body: customBodyFormatter
		},
		modifier: {
		    page: 'current'
		}
	    },
	    filename: fileName,
	    orientation: 'landscape'
	},
	{
	    extend: 'pdfHtml5',
	    text: '<i title="Download current page as PDF file" class="fa-regular fa-file-pdf fa-lg fa-fw"></i>',
	    className: 'btn btn-primary btn-sm',
	    orientation: 'landscape',
	    filename: fileName,
	    exportOptions: {
		columns: ':visible',
		format: {
		    body: customBodyFormatter
		},
		modifier: {
		    page: 'current'
		}
	    },
	    customize: function(doc) {
		// Identify the table in the exported content. If your table is not at index 1,
		// adjust this index accordingly.
		const table = doc.content.find(c => c.table);
		if (table) {
		    const colCount = table.table.body[0].length;
		    table.table.widths = Array(colCount).fill('auto');
		}
		// Optionally adjust font size and margins to help the table fit the page
		doc.defaultStyle.fontSize = 6;
		doc.pageMargins = [10, 10, 10, 10];
	    }
	}
    ],
    search: {
	regex: true,
	smart: true, },
    responsive: false,
    order: [
	[ 3, 'desc' ],
    	[ 1, 'asc' ]
    ],
    // "paging": false,
    // "scrolly": 400,
    select: true,
    // "displayLength": 25,
    lengthMenu: [[50, 100, -1], [50, 100, "All"]],
    infoCallback: function( settings, start, end, max, total, pre ) {
	var infostr= start +' to '+ end +' of total '+ total +' rows';
	return infostr;
    },
    createdRow: function ( row, data, index ) {
	if ( data[2] == 1 ) {
	    $(row).addClass('danger');
	}
    },
    columnDefs: [
	{
	    targets: 3, // Adjust this to the column index with icons
	    render: function (data, type, row, meta) {
		// For sorting and filtering, extract the icon's title attribute
		if (type === 'sort' || type === 'filter') {
		    // Create a temporary container
		    const div = document.createElement('div');
		    div.innerHTML = data;
		    const icon = div.querySelector('i');
		    if (icon && icon.getAttribute('title')) {
			return icon.getAttribute('title');
		    }
		    // If no icon title exists, fall back to plain text
		    return $(div).text();
		}
		// For display, return the full HTML
		return data;
	    }
	},
	{
            "targets": 0, // Target the first column
            "orderable": false, // Disable sorting on this column
            "searchable": false, // Disable searching on this column
            "data": null,
            "defaultContent": ""
	}
    ],
    rowCallback: function(row, data, index) {
	$('td:eq(0)', row).html(index + 1); // Add row number to the first column
    },
    // "serverSide": true,
    pagingType: "full_numbers"
} );

// Order by the grouping
$('#dataTableToDraw tbody').on( 'click', 'tr.group', function () {
    var currentOrder = table.order()[0];
    if ( currentOrder[0] === 2 && currentOrder[1] === 'asc' ) {
	table.order( [ 2, 'desc' ] ).draw();
    }
    else {
	table.order( [ 2, 'asc' ] ).draw();
    }
} );
