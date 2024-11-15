const reqPath = window.location.pathname;
const timestamp = new Date().toISOString().replace(/[-T:Z]/g, '').slice(0, 14);
const pathStrip = reqPath.replace(/^\/|\/$/g, '').replace(/\//g, '-');
const fileName = `${pathStrip}-${timestamp}`;

var table = $('#dataTableToDraw').DataTable({
    dom: "<'h6 col-12'i><'row'<'col m-0 p-0 btn-group'B><'col align-self-end'f>>" +
	"rt" + "<'row'<'col m-0 p-0'l><'col d-flex justify-content-end m-0 p-0'p>>",
    buttons: [
	{
	    extend: 'copyHtml5',
	    text: '<i title="Copy current page data to clipboard" class="fa-regular fa-copy fa-lg fa-fw"></i>',
	    className: 'btn btn-primary btn-sm',
	    exportOptions: {
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
	    exportOptions: {
		modifier: {
		    page: 'current'
		}
	    },
	    filename: fileName,
	    orientation: 'landscape'
	}
    ],
    search: {
	regex: true,
	smart: true, },
    responsive: false,
    order: [
	[ 3, 'asc' ],
    	[ 1, 'asc' ]
    ],
    // "paging": false,
    // "scrolly": 400,
    select: true,
    // "displayLength": 25,
    lengthMenu: [[50, 100, -1], [50, 100, "All"]],
    infoCallback: function( settings, start, end, max, total, pre ) {
	var infostr= start +' to '+ end +' of total'+ total +' rows';
	return infostr;
    },
    createdRow: function ( row, data, index ) {
	if ( data[2] == 1 ) {
	    $(row).addClass('danger');
	}
    },
    columnDefs: [
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
