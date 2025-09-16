document.addEventListener('DOMContentLoaded', () => {
    // ... (DOM elements and state are the same)

    // The apiFetch from utils.js will be used implicitly

    // ... (Stepper logic and validation functions are the same)

    async function handleCreateTenant() {
        if (!validateAndCollectStep(totalSteps)) {
            return;
        }
        showAlert('Creating tenant and admin user...', 'info');
        createBtn.disabled = true;
        createBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Creating...';

        try {
            // Step 1: Create the tenant
            const tenantDto = {
                companyName: onboardingData[1].companyName,
                subdomain: onboardingData[1].subdomain,
                country: onboardingData[1].country,
                currency: onboardingData[1].currency,
                timeZone: onboardingData[1].timeZone,
                plan: onboardingData[4].plan,
                mfaRequired: onboardingData[4].mfaRequired,
                popiaDpaAgreed: onboardingData[4].popiaDpaAgreed
            };

            const tenantResponse = await apiFetch('/onboarding/tenant', { method: 'POST', body: tenantDto });
            if (!tenantResponse.ok) {
                const errorData = await tenantResponse.json().catch(() => ({}));
                throw new Error(errorData.message || 'Failed to create tenant.');
            }
            const tenantData = await tenantResponse.json();
            showAlert(`Tenant created successfully with ID: ${tenantData.tenantId}`, 'success');

            // Step 2: Create the primary admin
            const adminDto = {
                tenantId: tenantData.tenantId,
                firstName: onboardingData[2].adminFirstName,
                lastName: onboardingData[2].adminLastName,
                email: onboardingData[2].adminWorkEmail,
                phone: onboardingData[2].adminPhone
            };

            const adminResponse = await apiFetch('/onboarding/admin', { method: 'POST', body: adminDto });
            if (!adminResponse.ok) {
                const errorData = await adminResponse.json().catch(() => ({}));
                throw new Error(errorData.message || 'Failed to create primary admin.');
            }
            const adminData = await adminResponse.json();
            showAlert(`Primary admin created successfully with ID: ${adminData.userId}`, 'success');

            // Step 3: Bulk invites (Placeholder)
            if (onboardingData[3].userInvites) {
                // TODO: Implement bulk invite API call
                console.log('Bulk invites not implemented. Data:', onboardingData[3].userInvites);
                showAlert('Bulk user invite endpoint is not yet implemented.', 'warning');
            }

            showAlert('Onboarding complete! You can now manage the new tenant and users.', 'success');
            createBtn.innerHTML = 'Done!';
            // Optional: Redirect or clear the form

        } catch (err) {
            showAlert(err.message || 'An unexpected error occurred during onboarding.', 'danger');
            createBtn.disabled = false;
            createBtn.innerHTML = 'Create Tenant & Send Invites';
        }
    }

    // ... (Event listeners are the same)

    // Initialize first step
    showStep(1);
});