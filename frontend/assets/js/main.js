// Main JavaScript file for InSecLabs Dashboard

class InSecLabsApp {
    constructor() {
        this.apiBaseUrl = '/api';
        this.currentUser = null;
        this.socket = null;
        this.init();
    }

    init() {
        // Check authentication status
        this.checkAuth();
        
        // Initialize tooltips
        this.initTooltips();
        
        // Initialize modals
        this.initModals();
        
        // Initialize form validation
        this.initForms();
        
        // Connect to WebSocket if authenticated
        if (this.currentUser) {
            this.connectWebSocket();
        }
    }

    checkAuth() {
        fetch('/api/auth/check-auth')
            .then(response => response.json())
            .then(data => {
                if (data.authenticated) {
                    this.currentUser = data.user;
                    this.updateUIForAuthenticatedUser();
                }
            })
            .catch(error => {
                console.error('Auth check failed:', error);
            });
    }

    updateUIForAuthenticatedUser() {
        // Update navigation
        const navItems = document.querySelectorAll('.nav-auth');
        navItems.forEach(item => {
            if (item.classList.contains('logged-in')) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });

        // Update user info
        const userElements = document.querySelectorAll('.user-info');
        userElements.forEach(element => {
            if (element.classList.contains('username')) {
                element.textContent = this.currentUser.username;
            }
            if (element.classList.contains('user-role')) {
                element.textContent = this.currentUser.role;
            }
        });
    }

    initTooltips() {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    initModals() {
        // Handle modal show events
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.addEventListener('show.bs.modal', (event) => {
                const button = event.relatedTarget;
                if (button) {
                    const modalType = button.getAttribute('data-modal-type');
                    this.loadModalContent(modalType, modal);
                }
            });
        });
    }

    loadModalContent(modalType, modalElement) {
        switch (modalType) {
            case 'new-scan':
                this.loadNewScanModal(modalElement);
                break;
            case 'scan-results':
                this.loadScanResultsModal(modalElement);
                break;
            case 'settings':
                this.loadSettingsModal(modalElement);
                break;
        }
    }

    initForms() {
        // Login form
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }

        // Register form
        const registerForm = document.getElementById('register-form');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleRegister();
            });
        }

        // New scan form
        const scanForm = document.getElementById('new-scan-form');
        if (scanForm) {
            scanForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleNewScan();
            });
        }
    }

    async handleLogin() {
        const form = document.getElementById('login-form');
        const formData = new FormData(form);
        const data = {
            username: formData.get('username'),
            password: formData.get('password'),
            remember: formData.get('remember') === 'on'
        };

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data),
                credentials: 'include'
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast('Login successful!', 'success');
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            } else {
                this.showToast(result.error, 'danger');
            }
        } catch (error) {
            this.showToast('Login failed. Please try again.', 'danger');
        }
    }

    async handleRegister() {
        const form = document.getElementById('register-form');
        const formData = new FormData(form);
        const data = {
            username: formData.get('username'),
            email: formData.get('email'),
            password: formData.get('password'),
            confirm_password: formData.get('confirm_password')
        };

        // Validate passwords match
        if (data.password !== data.confirm_password) {
            this.showToast('Passwords do not match', 'warning');
            return;
        }

        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: data.username,
                    email: data.email,
                    password: data.password
                })
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast('Registration successful! Please login.', 'success');
                setTimeout(() => {
                    window.location.href = '/login';
                }, 1500);
            } else {
                this.showToast(result.error, 'danger');
            }
        } catch (error) {
            this.showToast('Registration failed. Please try again.', 'danger');
        }
    }

    async handleNewScan() {
        const form = document.getElementById('new-scan-form');
        const formData = new FormData(form);
        
        const data = {
            target_id: formData.get('target_id'),
            scan_type: formData.get('scan_type'),
            scan_config: {
                depth: formData.get('scan_depth'),
                intensity: formData.get('scan_intensity'),
                notify_on_complete: formData.get('notify_on_complete') === 'on'
            }
        };

        try {
            const response = await fetch('/api/scans/scans', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data),
                credentials: 'include'
            });

            const result = await response.json();
            
            if (result.success) {
                this.showToast('Scan started successfully!', 'success');
                
                // Close modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('newScanModal'));
                modal.hide();
                
                // Redirect to scan page
                setTimeout(() => {
                    window.location.href = `/scan/${result.scan.id}`;
                }, 1000);
            } else {
                this.showToast(result.error, 'danger');
            }
        } catch (error) {
            this.showToast('Failed to start scan. Please try again.', 'danger');
        }
    }

    connectWebSocket() {
        // Connect to WebSocket server
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to WebSocket server');
        });
        
        this.socket.on('scan_update', (data) => {
            this.handleScanUpdate(data);
        });
        
        this.socket.on('new_notification', (data) => {
            this.handleNewNotification(data);
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from WebSocket server');
        });
    }

    handleScanUpdate(data) {
        // Update scan progress in UI
        const scanElement = document.querySelector(`[data-scan-id="${data.scan_id}"]`);
        if (scanElement) {
            const progressBar = scanElement.querySelector('.progress-bar');
            const statusBadge = scanElement.querySelector('.scan-status');
            
            if (progressBar) {
                progressBar.style.width = `${data.progress}%`;
                progressBar.textContent = `${data.progress}%`;
            }
            
            if (statusBadge) {
                statusBadge.textContent = data.status;
                statusBadge.className = `badge bg-${this.getStatusColor(data.status)}`;
            }
        }
        
        // Show notification for completed scans
        if (data.status === 'completed') {
            this.showToast(`Scan ${data.scan_id} completed!`, 'success');
        } else if (data.status === 'failed') {
            this.showToast(`Scan ${data.scan_id} failed!`, 'danger');
        }
    }

    handleNewNotification(data) {
        // Show notification toast
        this.showToast(data.message, 'info');
        
        // Update notification badge
        const badge = document.querySelector('.notification-badge');
        if (badge) {
            const currentCount = parseInt(badge.textContent) || 0;
            badge.textContent = currentCount + 1;
            badge.style.display = 'flex';
        }
    }

    getStatusColor(status) {
        const colors = {
            'queued': 'secondary',
            'running': 'info',
            'completed': 'success',
            'failed': 'danger',
            'timeout': 'warning'
        };
        return colors[status] || 'secondary';
    }

    showToast(message, type = 'info') {
        // Create toast element
        const toastId = 'toast-' + Date.now();
        const toastHtml = `
            <div id="${toastId}" class="toast align-items-center text-bg-${type} border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `;
        
        // Add to toast container
        const container = document.querySelector('.toast-container') || this.createToastContainer();
        container.innerHTML += toastHtml;
        
        // Show toast
        const toastElement = document.getElementById(toastId);
        const toast = new bootstrap.Toast(toastElement, {
            autohide: true,
            delay: 5000
        });
        toast.show();
        
        // Remove toast after hide
        toastElement.addEventListener('hidden.bs.toast', () => {
            toastElement.remove();
        });
    }

    createToastContainer() {
        const container = document.createElement('div');
        container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '1055';
        document.body.appendChild(container);
        return container;
    }

    async loadDashboardStats() {
        try {
            const response = await fetch('/api/scans/dashboard/stats', {
                credentials: 'include'
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.updateDashboardStats(result);
            }
        } catch (error) {
            console.error('Failed to load dashboard stats:', error);
        }
    }

    updateDashboardStats(data) {
        // Update statistics cards
        const stats = data.statistics;
        
        // Update total targets
        const targetsElement = document.querySelector('[data-stat="total_targets"]');
        if (targetsElement) targetsElement.textContent = stats.total_targets;
        
        // Update total scans
        const scansElement = document.querySelector('[data-stat="total_scans"]');
        if (scansElement) scansElement.textContent = stats.total_scans;
        
        // Update active scans
        const activeElement = document.querySelector('[data-stat="active_scans"]');
        if (activeElement) activeElement.textContent = stats.active_scans;
        
        // Update vulnerabilities by severity
        const vulnStats = stats.vulnerabilities;
        const severityElements = {
            'critical': document.querySelector('[data-stat="vuln_critical"]'),
            'high': document.querySelector('[data-stat="vuln_high"]'),
            'medium': document.querySelector('[data-stat="vuln_medium"]'),
            'low': document.querySelector('[data-stat="vuln_low"]'),
            'info': document.querySelector('[data-stat="vuln_info"]')
        };
        
        for (const [severity, element] of Object.entries(severityElements)) {
            if (element) {
                element.textContent = vulnStats[severity] || 0;
            }
        }
        
        // Update recent scans list
        this.updateRecentScans(data.recent_scans);
    }

    updateRecentScans(scans) {
        const container = document.querySelector('#recent-scans-list');
        if (!container) return;
        
        container.innerHTML = '';
        
        scans.forEach(scan => {
            const scanElement = document.createElement('div');
            scanElement.className = 'activity-item';
            scanElement.classList.add(scan.status === 'completed' ? 'success' : 
                                    scan.status === 'failed' ? 'danger' : 'warning');
            
            scanElement.innerHTML = `
                <div class="d-flex justify-content-between">
                    <strong>${scan.target}</strong>
                    <span class="activity-time">${this.formatTime(scan.start_time)}</span>
                </div>
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge bg-${this.getStatusColor(scan.status)}">
                        ${scan.status}
                    </span>
                    <span>Progress: ${scan.progress}%</span>
                </div>
            `;
            
            container.appendChild(scanElement);
        });
    }

    formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} minutes ago`;
        
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours} hours ago`;
        
        const diffDays = Math.floor(diffHours / 24);
        if (diffDays < 7) return `${diffDays} days ago`;
        
        return date.toLocaleDateString();
    }

    logout() {
        fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include'
        })
        .then(() => {
            window.location.href = '/login';
        })
        .catch(error => {
            console.error('Logout failed:', error);
        });
    }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new InSecLabsApp();
});
