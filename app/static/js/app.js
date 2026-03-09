/* NinjaScan — Upload handling and dynamic UI */

(function () {
    'use strict';

    const dropZone   = document.getElementById('drop-zone');
    const fileInput  = document.getElementById('file-input');
    const browseBtn  = document.getElementById('browse-btn');
    const clearBtn   = document.getElementById('clear-file');
    const scanBtn    = document.getElementById('scan-btn');
    const fileInfo   = document.getElementById('file-info');
    const fileName   = document.getElementById('file-name');
    const fileSizeEl = document.getElementById('file-size');
    const progress   = document.getElementById('upload-progress');
    const progressBar = document.getElementById('progress-bar');
    const progressPct = document.getElementById('progress-pct');
    const progressLabel = document.getElementById('progress-label');
    const errorBox   = document.getElementById('upload-error');

    if (!dropZone) return; // Not on the upload page

    const MAX_SIZE = 50 * 1024 * 1024; // 50MB
    let selectedFile = null;

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }

    function showError(msg) {
        errorBox.textContent = msg;
        errorBox.classList.remove('d-none');
    }

    function clearError() {
        errorBox.textContent = '';
        errorBox.classList.add('d-none');
    }

    function setFile(file) {
        if (!file) return;
        if (file.size > MAX_SIZE) {
            showError('File is too large. Maximum allowed size is 50 MB.');
            return;
        }
        selectedFile = file;
        clearError();
        fileName.textContent = file.name;
        fileSizeEl.textContent = formatBytes(file.size);
        fileInfo.classList.remove('d-none');
        scanBtn.disabled = false;
    }

    function resetUpload() {
        selectedFile = null;
        fileInput.value = '';
        fileInfo.classList.add('d-none');
        scanBtn.disabled = true;
        progress.classList.add('d-none');
        progressBar.style.width = '0%';
        clearError();
    }

    // Browse button
    browseBtn.addEventListener('click', () => fileInput.click());

    // Drop zone click
    dropZone.addEventListener('click', (e) => {
        if (e.target !== browseBtn && !browseBtn.contains(e.target)) {
            fileInput.click();
        }
    });

    // File input change
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) setFile(fileInput.files[0]);
    });

    // Clear button
    clearBtn.addEventListener('click', resetUpload);

    // Drag and drop events
    ['dragenter', 'dragover'].forEach(ev => {
        dropZone.addEventListener(ev, (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });
    });
    ['dragleave', 'drop'].forEach(ev => {
        dropZone.addEventListener(ev, (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
        });
    });
    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) setFile(files[0]);
    });

    // Scan button click
    scanBtn.addEventListener('click', () => {
        if (!selectedFile) return;

        const formData = new FormData();
        formData.append('file', selectedFile);

        scanBtn.disabled = true;
        clearError();
        progress.classList.remove('d-none');
        progressLabel.textContent = 'Uploading...';

        const xhr = new XMLHttpRequest();

        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const pct = Math.round((e.loaded / e.total) * 50); // upload = 0-50%
                progressBar.style.width = pct + '%';
                progressPct.textContent = pct + '%';
            }
        });

        xhr.addEventListener('load', () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                progressBar.style.width = '70%';
                progressPct.textContent = '70%';
                progressLabel.textContent = 'Analyzing...';

                let data;
                try {
                    data = JSON.parse(xhr.responseText);
                } catch (err) {
                    showError('Unexpected server response.');
                    scanBtn.disabled = false;
                    return;
                }

                if (data.error) {
                    showError(data.error);
                    progress.classList.add('d-none');
                    scanBtn.disabled = false;
                    return;
                }

                // Simulate analysis progress
                let pct = 70;
                const interval = setInterval(() => {
                    pct = Math.min(pct + 5, 95);
                    progressBar.style.width = pct + '%';
                    progressPct.textContent = pct + '%';
                }, 200);

                setTimeout(() => {
                    clearInterval(interval);
                    progressBar.style.width = '100%';
                    progressPct.textContent = '100%';
                    progressLabel.textContent = 'Done! Redirecting...';
                    window.location.href = data.redirect;
                }, 1500);
            } else {
                let errMsg = 'Upload failed.';
                try {
                    const data = JSON.parse(xhr.responseText);
                    if (data.error) errMsg = data.error;
                } catch (e) {}
                showError(errMsg);
                progress.classList.add('d-none');
                scanBtn.disabled = false;
            }
        });

        xhr.addEventListener('error', () => {
            showError('Network error. Please try again.');
            progress.classList.add('d-none');
            scanBtn.disabled = false;
        });

        xhr.open('POST', '/upload');
        xhr.send(formData);
    });
})();
