/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* The component responsible for rendering the actual modals */
import React from 'react';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import DeletePolicyModal from 'Components/modals/DeletePolicyModal';
import DeleteUserModal from 'Components/modals/DeleteUserModal';
import ResetUserPasswordModal from 'Components/modals/ResetUserPasswordModal';
import DeleteComplianceSourceModal from 'Components/modals/DeleteComplianceSourceModal';
import DeleteLogSourceModal from 'Components/modals/DeleteLogSourceModal';
import DeleteDestinationModal from 'Components/modals/DeleteDestinationModal';
import DeleteRuleModal from 'Components/modals/DeleteRuleModal';
import NetworkErrorModal from 'Components/modals/NetworkErrorModal';
import AnalyticsConsentModal from 'Components/modals/AnalyticsConsentModal';

const ModalManager: React.FC = () => {
  const { state: modalState } = useModal();
  if (!modalState.modal) {
    return null;
  }
  let Component;
  switch (modalState.modal) {
    case MODALS.DELETE_COMPLIANCE_SOURCE:
      Component = DeleteComplianceSourceModal;
      break;
    case MODALS.DELETE_LOG_SOURCE:
      Component = DeleteLogSourceModal;
      break;
    case MODALS.DELETE_USER:
      Component = DeleteUserModal;
      break;
    case MODALS.RESET_USER_PASS:
      Component = ResetUserPasswordModal;
      break;
    case MODALS.DELETE_RULE:
      Component = DeleteRuleModal;
      break;
    case MODALS.DELETE_DESTINATION:
      Component = DeleteDestinationModal;
      break;
    case MODALS.NETWORK_ERROR:
      Component = NetworkErrorModal;
      break;
    case MODALS.ANALYTICS_CONSENT:
      Component = AnalyticsConsentModal;
      break;
    case MODALS.DELETE_POLICY:
    default:
      Component = DeletePolicyModal;
      break;
  }

  return <Component {...modalState.props} />;
};

export default ModalManager;
