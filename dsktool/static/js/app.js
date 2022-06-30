// $(function () {
//     console.log("Hello!");
// });

// $(function () {
//     toggleDivs("byCrsUsr");
// });

function toggleDivs(anyDiv) {
    divArray = ['byCrsUsr', 'byCrs', 'byUsr'];
  if (!anyDiv == null) {
    for (index = 0; index < divArray.length; index++) { 
      if (divArray[index] === anyDiv) {
        document.getElementById(divArray[index]).style.display = "inline";
        // console.log("ACTIVE DIV: " + divArray[index]);
        activeDiv = divArray[index];
        $("#byCrsUsrRb").prop("checked", true);
        $("#resultsTableBody").empty();
        $("#updateTableBody").empty();
        $("#searchValueCrstoSearch").val("");
        $("#searchValueUsrtoSearch").val("");
        $("#searchValueUsr").val("");
        $("#searchValueCrs").val("");
        $("#resultsTable").hide();
        $("#searchUpdate").hide();
        $("#updateResults").hide();
        $("#processBlock").hide();
        $("#checkAll").prop("checked", false);
        $("#isUpdateRequired1").prop("checked", false);
        $("#isAvailabilityUpdateRequired1").prop("checked", false);
        $("#isDataSourceKeyUpdateRequired1").prop("checked", false);
  
        // if byCrsUsr or byCrs set result-table-header and update-table-header to what they are now - user info centric
        // if byUsr set result-table-header and update-table-header to reflect course info \not\ user-centric info
  
        if ( (activeDiv == "byCrsUsr") || (activeDiv == "byCrs")) {
          // console.log("SETTING result-table and update-table headers for Course Memberships");
          $("#resp-table-header").empty();
          $("#update-table-header").empty();
  
          let respTableHdr = '<div class="divTableHead">Select to Process</div>' +
            '<div class="divTableHead">Available</div>' +
            '<div class="divTableHead">External Id</div>' +
            '<div class="divTableHead">Username</div>' +
            '<div class="divTableHead">User First Name</div>' +
            '<div class="divTableHead">User Middle Name</div>' +
            '<div class="divTableHead">User Last Name</div>' +
            '<div class="divTableHead">User Email</div>' +
            '<div class="divTableHead">Membership Data Source</div>' +
            '<div class="divTableHead">Date Membership Modified</div>';
          $("#resp-table-header").append(respTableHdr);
          
          let updateTableHdr = '<div class="divTableHead">Available</div>' +
            '<div class="divTableHead">External Id</div>' +
            '<div class="divTableHead">Username</div>' +
            '<div class="divTableHead">User First Name</div>' +
            '<div class="divTableHead">User Middle Name</div>' +
            '<div class="divTableHead">User Last Name</div>' +
            '<div class="divTableHead">User Email</div>' +
            '<div class="divTableHead">Membership Data Source</div>' +
            '<div class="divTableHead">Date Membership Modified</div>';
          $("#update-table-header").append(updateTableHdr);
  
  
        } else if (activeDiv == "byUsr") {
          // console.log("SETTING result-table and update-table headers for User Memberships");
          $("#resp-table-header").empty();
          $("#update-table-header").empty();
  
          let respTableHdr = '<div class="divTableHead">Select to Process</div>' +
            '<div class="divTableHead">Available</div>' +
            '<div class="divTableHead">Course External Id</div>' +
            '<div class="divTableHead">Course Name</div>' +
            '<div class="divTableHead">User Course Role</div>' +
            '<div class="divTableHead">Membership Data Source</div>' +
            '<div class="divTableHead">Date Membership Modified</div>';
          $("#resp-table-header").append(respTableHdr);
  
          let updateTableHdr = '<div class="divTableHead">Available</div>' +
            '<div class="divTableHead">Course External Id</div>' +
            '<div class="divTableHead">Course Name</div>' +
            '<div class="divTableHead">User Course Role</div>' +
            '<div class="divTableHead">Membership Data Source</div>' +
            '<div class="divTableHead">Date Membership Modified</div>';
          $("#update-table-header").append(updateTableHdr);
  
        }
  
      } else {
        document.getElementById(divArray[index]).style.display = "none"; 
      }
    }
  }
}