function searchShow(){
	document.getElementById("search_div").style.display = "block";
	document.getElementById("file_div").style.display = "none";
}

function fileShow(){
	document.getElementById("search_div").style.display = "none";
	document.getElementById("file_div").style.display = "block";
}

function sampleshow(){
	document.getElementById("sampleinfo").style.display = "block";
	document.getElementById("classinfo").style.display = "none";
}

function classshow(){
	document.getElementById("sampleinfo").style.display = "none";
	document.getElementById("classinfo").style.display = "block";
}
