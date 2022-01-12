/*
 * (C) 2021-2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved.
 *
 * Author: Neels Janosch Hofmeyr <nhofmeyr@sysmocom.de>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/pfcp/pfcp_strs.h>

const struct value_string osmo_pfcp_message_type_strs[] = {
	{ OSMO_PFCP_MSGT_HEARTBEAT_REQ, "HEARTBEAT_REQ" },
	{ OSMO_PFCP_MSGT_HEARTBEAT_RESP, "HEARTBEAT_RESP" },
	{ OSMO_PFCP_MSGT_PFD_MGMT_REQ, "PFD_MGMT_REQ" },
	{ OSMO_PFCP_MSGT_PFD_MGMT_RESP, "PFD_MGMT_RESP" },
	{ OSMO_PFCP_MSGT_ASSOC_SETUP_REQ, "ASSOC_SETUP_REQ" },
	{ OSMO_PFCP_MSGT_ASSOC_SETUP_RESP, "ASSOC_SETUP_RESP" },
	{ OSMO_PFCP_MSGT_ASSOC_UPDATE_REQ, "ASSOC_UPDATE_REQ" },
	{ OSMO_PFCP_MSGT_ASSOC_UPDATE_RESP, "ASSOC_UPDATE_RESP" },
	{ OSMO_PFCP_MSGT_ASSOC_RELEASE_REQ, "ASSOC_RELEASE_REQ" },
	{ OSMO_PFCP_MSGT_ASSOC_RELEASE_RESP, "ASSOC_RELEASE_RESP" },
	{ OSMO_PFCP_MSGT_VERSION_NOT_SUPP_RESP, "VERSION_NOT_SUPP_RESP" },
	{ OSMO_PFCP_MSGT_NODE_REPORT_REQ, "NODE_REPORT_REQ" },
	{ OSMO_PFCP_MSGT_NODE_REPORT_RESP, "NODE_REPORT_RESP" },
	{ OSMO_PFCP_MSGT_SESSION_SET_DEL_REQ, "SESSION_SET_DEL_REQ" },
	{ OSMO_PFCP_MSGT_SESSION_SET_DEL_RESP, "SESSION_SET_DEL_RESP" },
	{ OSMO_PFCP_MSGT_SESSION_EST_REQ, "SESSION_EST_REQ" },
	{ OSMO_PFCP_MSGT_SESSION_EST_RESP, "SESSION_EST_RESP" },
	{ OSMO_PFCP_MSGT_SESSION_MOD_REQ, "SESSION_MOD_REQ" },
	{ OSMO_PFCP_MSGT_SESSION_MOD_RESP, "SESSION_MOD_RESP" },
	{ OSMO_PFCP_MSGT_SESSION_DEL_REQ, "SESSION_DEL_REQ" },
	{ OSMO_PFCP_MSGT_SESSION_DEL_RESP, "SESSION_DEL_RESP" },
	{ OSMO_PFCP_MSGT_SESSION_REP_REQ, "SESSION_REP_REQ" },
	{ OSMO_PFCP_MSGT_SESSION_REP_RESP, "SESSION_REP_RESP" },
	{ 0 }
};

const struct value_string osmo_pfcp_iei_strs[] = {
	{ OSMO_PFCP_IEI_CREATE_PDR, "Create PDR" },
	{ OSMO_PFCP_IEI_PDI, "PDI" },
	{ OSMO_PFCP_IEI_CREATE_FAR, "Create FAR" },
	{ OSMO_PFCP_IEI_FORW_PARAMS, "Forwarding Parameters" },
	{ OSMO_PFCP_IEI_DUPL_PARAMS, "Duplicating Parameters" },
	{ OSMO_PFCP_IEI_CREATE_URR, "Create URR" },
	{ OSMO_PFCP_IEI_CREATE_QER, "Create QER" },
	{ OSMO_PFCP_IEI_CREATED_PDR, "Created PDR" },
	{ OSMO_PFCP_IEI_UPD_PDR, "Update PDR" },
	{ OSMO_PFCP_IEI_UPD_FAR, "Update FAR" },
	{ OSMO_PFCP_IEI_UPD_FORW_PARAMS, "Update Forwarding Parameters" },
	{ OSMO_PFCP_IEI_UPD_BAR_SESS_REP_RESP, "Update BAR (PFCP Session Report Response)" },
	{ OSMO_PFCP_IEI_UPD_URR, "Update URR" },
	{ OSMO_PFCP_IEI_UPD_QER, "Update QER" },
	{ OSMO_PFCP_IEI_REMOVE_PDR, "Remove PDR" },
	{ OSMO_PFCP_IEI_REMOVE_FAR, "Remove FAR" },
	{ OSMO_PFCP_IEI_REMOVE_URR, "Remove URR" },
	{ OSMO_PFCP_IEI_REMOVE_QER, "Remove QER" },
	{ OSMO_PFCP_IEI_CAUSE, "Cause" },
	{ OSMO_PFCP_IEI_SOURCE_IFACE, "Source Interface" },
	{ OSMO_PFCP_IEI_F_TEID, "F-TEID" },
	{ OSMO_PFCP_IEI_NETWORK_INST, "Network Instance" },
	{ OSMO_PFCP_IEI_SDF_FILTER, "SDF Filter" },
	{ OSMO_PFCP_IEI_APPLICATION_ID, "Application ID" },
	{ OSMO_PFCP_IEI_GATE_STATUS, "Gate Status" },
	{ OSMO_PFCP_IEI_MBR, "MBR" },
	{ OSMO_PFCP_IEI_GBR, "GBR" },
	{ OSMO_PFCP_IEI_QER_CORRELATION_ID, "QER Correlation ID" },
	{ OSMO_PFCP_IEI_PRECEDENCE, "Precedence" },
	{ OSMO_PFCP_IEI_TRANSPORT_LEVEL_MARKING, "Transport Level Marking" },
	{ OSMO_PFCP_IEI_VOLUME_THRESH, "Volume Threshold" },
	{ OSMO_PFCP_IEI_TIME_THRESH, "Time Threshold" },
	{ OSMO_PFCP_IEI_MONITORING_TIME, "Monitoring Time" },
	{ OSMO_PFCP_IEI_SUBSEQUENT_VOLUME_THRESH, "Subsequent Volume Threshold" },
	{ OSMO_PFCP_IEI_SUBSEQUENT_TIME_THRESH, "Subsequent Time Threshold" },
	{ OSMO_PFCP_IEI_INACT_DETECTION_TIME, "Inactivity Detection Time" },
	{ OSMO_PFCP_IEI_REPORTING_TRIGGERS, "Reporting Triggers" },
	{ OSMO_PFCP_IEI_REDIRECT_INFO, "Redirect Information" },
	{ OSMO_PFCP_IEI_REP_TYPE, "Report Type" },
	{ OSMO_PFCP_IEI_OFFENDING_IE, "Offending IE" },
	{ OSMO_PFCP_IEI_FORW_POLICY, "Forwarding Policy" },
	{ OSMO_PFCP_IEI_DESTINATION_IFACE, "Destination Interface" },
	{ OSMO_PFCP_IEI_UP_FUNCTION_FEATURES, "UP Function Features" },
	{ OSMO_PFCP_IEI_APPLY_ACTION, "Apply Action" },
	{ OSMO_PFCP_IEI_DL_DATA_SERVICE_INFO, "Downlink Data Service Information" },
	{ OSMO_PFCP_IEI_DL_DATA_NOTIFICATION_DELAY, "Downlink Data Notification Delay" },
	{ OSMO_PFCP_IEI_DL_BUFF_DURATION, "DL Buffering Duration" },
	{ OSMO_PFCP_IEI_DL_BUFF_SUGGESTED_PACKET_COUNT, "DL Buffering Suggested Packet Count" },
	{ OSMO_PFCP_IEI_PFCPSMREQ_FLAGS, "PFCPSMReq-Flags" },
	{ OSMO_PFCP_IEI_PFCPSRRSP_FLAGS, "PFCPSRRsp-Flags" },
	{ OSMO_PFCP_IEI_LOAD_CTRL_INFO, "Load Control Information" },
	{ OSMO_PFCP_IEI_SEQUENCE_NUMBER, "Sequence Number" },
	{ OSMO_PFCP_IEI_METRIC, "Metric" },
	{ OSMO_PFCP_IEI_OVERLOAD_CTRL_INFO, "Overload Control Information" },
	{ OSMO_PFCP_IEI_TIMER, "Timer" },
	{ OSMO_PFCP_IEI_PDR_ID, "PDR ID" },
	{ OSMO_PFCP_IEI_F_SEID, "F-SEID" },
	{ OSMO_PFCP_IEI_APPLICATION_IDS_PFDS, "Application ID's PFDs" },
	{ OSMO_PFCP_IEI_PFD_CONTEXT, "PFD context" },
	{ OSMO_PFCP_IEI_NODE_ID, "Node ID" },
	{ OSMO_PFCP_IEI_PFD_CONTENTS, "PFD contents" },
	{ OSMO_PFCP_IEI_MEAS_METHOD, "Measurement Method" },
	{ OSMO_PFCP_IEI_USAGE_REP_TRIGGER, "Usage Report Trigger" },
	{ OSMO_PFCP_IEI_MEAS_PERIOD, "Measurement Period" },
	{ OSMO_PFCP_IEI_FQ_CSID, "FQ-CSID" },
	{ OSMO_PFCP_IEI_VOLUME_MEAS, "Volume Measurement" },
	{ OSMO_PFCP_IEI_DURATION_MEAS, "Duration Measurement" },
	{ OSMO_PFCP_IEI_APPLICATION_DETECTION_INFO, "Application Detection Information" },
	{ OSMO_PFCP_IEI_TIME_OF_FIRST_PACKET, "Time of First Packet" },
	{ OSMO_PFCP_IEI_TIME_OF_LAST_PACKET, "Time of Last Packet" },
	{ OSMO_PFCP_IEI_QUOTA_HOLDING_TIME, "Quota Holding Time" },
	{ OSMO_PFCP_IEI_DROPPED_DL_TRAFFIC_THRESH, "Dropped DL Traffic Threshold" },
	{ OSMO_PFCP_IEI_VOLUME_QUOTA, "Volume Quota" },
	{ OSMO_PFCP_IEI_TIME_QUOTA, "Time Quota" },
	{ OSMO_PFCP_IEI_START_TIME, "Start Time" },
	{ OSMO_PFCP_IEI_END_TIME, "End Time" },
	{ OSMO_PFCP_IEI_QUERY_URR, "Query URR" },
	{ OSMO_PFCP_IEI_USAGE_REP_SESS_MOD_RESP, "Usage Report (Session Modification Response)" },
	{ OSMO_PFCP_IEI_USAGE_REP_SESS_DEL_RESP, "Usage Report (Session Deletion Response)" },
	{ OSMO_PFCP_IEI_USAGE_REP_SESS_REP_REQ, "Usage Report (Session Report Request)" },
	{ OSMO_PFCP_IEI_URR_ID, "URR ID" },
	{ OSMO_PFCP_IEI_LINKED_URR_ID, "Linked URR ID" },
	{ OSMO_PFCP_IEI_DL_DATA_REP, "Downlink Data Report" },
	{ OSMO_PFCP_IEI_OUTER_HEADER_CREATION, "Outer Header Creation" },
	{ OSMO_PFCP_IEI_CREATE_BAR, "Create BAR" },
	{ OSMO_PFCP_IEI_UPD_BAR_SESS_MOD_REQ, "Update BAR (Session Modification Request)" },
	{ OSMO_PFCP_IEI_REMOVE_BAR, "Remove BAR" },
	{ OSMO_PFCP_IEI_BAR_ID, "BAR ID" },
	{ OSMO_PFCP_IEI_CP_FUNCTION_FEATURES, "CP Function Features" },
	{ OSMO_PFCP_IEI_USAGE_INFO, "Usage Information" },
	{ OSMO_PFCP_IEI_APPLICATION_INST_ID, "Application Instance ID" },
	{ OSMO_PFCP_IEI_FLOW_INFO, "Flow Information" },
	{ OSMO_PFCP_IEI_UE_IP_ADDRESS, "UE IP Address" },
	{ OSMO_PFCP_IEI_PACKET_RATE, "Packet Rate" },
	{ OSMO_PFCP_IEI_OUTER_HEADER_REMOVAL, "Outer Header Removal" },
	{ OSMO_PFCP_IEI_RECOVERY_TIME_STAMP, "Recovery Time Stamp" },
	{ OSMO_PFCP_IEI_DL_FLOW_LEVEL_MARKING, "DL Flow Level Marking" },
	{ OSMO_PFCP_IEI_HEADER_ENRICHMENT, "Header Enrichment" },
	{ OSMO_PFCP_IEI_ERROR_IND_REP, "Error Indication Report" },
	{ OSMO_PFCP_IEI_MEAS_INFO, "Measurement Information" },
	{ OSMO_PFCP_IEI_NODE_REP_TYPE, "Node Report Type" },
	{ OSMO_PFCP_IEI_USER_PLANE_PATH_FAILURE_REP, "User Plane Path Failure Report" },
	{ OSMO_PFCP_IEI_REMOTE_GTP_U_PEER, "Remote GTP-U Peer" },
	{ OSMO_PFCP_IEI_UR_SEQN, "UR-SEQN" },
	{ OSMO_PFCP_IEI_UPD_DUPL_PARAMS, "Update Duplicating Parameters" },
	{ OSMO_PFCP_IEI_ACTIVATE_PREDEFINED_RULES, "Activate Predefined Rules" },
	{ OSMO_PFCP_IEI_DEACTIVATE_PREDEFINED_RULES, "Deactivate Predefined Rules" },
	{ OSMO_PFCP_IEI_FAR_ID, "FAR ID" },
	{ OSMO_PFCP_IEI_QER_ID, "QER ID" },
	{ OSMO_PFCP_IEI_OCI_FLAGS, "OCI Flags" },
	{ OSMO_PFCP_IEI_PFCP_ASSOC_RELEASE_REQ, "PFCP Association Release Request" },
	{ OSMO_PFCP_IEI_GRACEFUL_RELEASE_PERIOD, "Graceful Release Period" },
	{ OSMO_PFCP_IEI_PDN_TYPE, "PDN Type" },
	{ OSMO_PFCP_IEI_FAILED_RULE_ID, "Failed Rule ID" },
	{ OSMO_PFCP_IEI_TIME_QUOTA_MECHANISM, "Time Quota Mechanism" },
	{ OSMO_PFCP_IEI_RESERVED, "Reserved" },
	{ OSMO_PFCP_IEI_USER_PLANE_INACT_TIMER, "User Plane Inactivity Timer" },
	{ OSMO_PFCP_IEI_AGGREGATED_URRS, "Aggregated URRs" },
	{ OSMO_PFCP_IEI_MULTIPLIER, "Multiplier" },
	{ OSMO_PFCP_IEI_AGGREGATED_URR_ID, "Aggregated URR ID" },
	{ OSMO_PFCP_IEI_SUBSEQUENT_VOLUME_QUOTA, "Subsequent Volume Quota" },
	{ OSMO_PFCP_IEI_SUBSEQUENT_TIME_QUOTA, "Subsequent Time Quota" },
	{ OSMO_PFCP_IEI_RQI, "RQI" },
	{ OSMO_PFCP_IEI_QFI, "QFI" },
	{ OSMO_PFCP_IEI_QUERY_URR_REFERENCE, "Query URR Reference" },
	{ OSMO_PFCP_IEI_ADDITIONAL_USAGE_REPS_INFO, "Additional Usage Reports Information" },
	{ OSMO_PFCP_IEI_CREATE_TRAFFIC_ENDPOINT, "Create Traffic Endpoint" },
	{ OSMO_PFCP_IEI_CREATED_TRAFFIC_ENDPOINT, "Created Traffic Endpoint" },
	{ OSMO_PFCP_IEI_UPD_TRAFFIC_ENDPOINT, "Update Traffic Endpoint" },
	{ OSMO_PFCP_IEI_REMOVE_TRAFFIC_ENDPOINT, "Remove Traffic Endpoint" },
	{ OSMO_PFCP_IEI_TRAFFIC_ENDPOINT_ID, "Traffic Endpoint ID" },
	{ OSMO_PFCP_IEI_ETHERNET_PACKET_FILTER, "Ethernet Packet Filter" },
	{ OSMO_PFCP_IEI_MAC_ADDRESS, "MAC address" },
	{ OSMO_PFCP_IEI_C_TAG, "C-TAG" },
	{ OSMO_PFCP_IEI_S_TAG, "S-TAG" },
	{ OSMO_PFCP_IEI_ETHERTYPE, "Ethertype" },
	{ OSMO_PFCP_IEI_PROXYING, "Proxying" },
	{ OSMO_PFCP_IEI_ETHERNET_FILTER_ID, "Ethernet Filter ID" },
	{ OSMO_PFCP_IEI_ETHERNET_FILTER_PROPERTIES, "Ethernet Filter Properties" },
	{ OSMO_PFCP_IEI_SUGGESTED_BUFF_PACKETS_COUNT, "Suggested Buffering Packets Count" },
	{ OSMO_PFCP_IEI_USER_ID, "User ID" },
	{ OSMO_PFCP_IEI_ETHERNET_PDU_SESS_INFO, "Ethernet PDU Session Information" },
	{ OSMO_PFCP_IEI_ETHERNET_TRAFFIC_INFO, "Ethernet Traffic Information" },
	{ OSMO_PFCP_IEI_MAC_ADDRS_DETECTED, "MAC Addresses Detected" },
	{ OSMO_PFCP_IEI_MAC_ADDRS_REMOVED, "MAC Addresses Removed" },
	{ OSMO_PFCP_IEI_ETHERNET_INACT_TIMER, "Ethernet Inactivity Timer" },
	{ OSMO_PFCP_IEI_ADDITIONAL_MONITORING_TIME, "Additional Monitoring Time" },
	{ OSMO_PFCP_IEI_EVENT_QUOTA, "Event Quota" },
	{ OSMO_PFCP_IEI_EVENT_THRESH, "Event Threshold" },
	{ OSMO_PFCP_IEI_SUBSEQUENT_EVENT_QUOTA, "Subsequent Event Quota" },
	{ OSMO_PFCP_IEI_SUBSEQUENT_EVENT_THRESH, "Subsequent Event Threshold" },
	{ OSMO_PFCP_IEI_TRACE_INFO, "Trace Information" },
	{ OSMO_PFCP_IEI_FRAMED_ROUTE, "Framed-Route" },
	{ OSMO_PFCP_IEI_FRAMED_ROUTING, "Framed-Routing" },
	{ OSMO_PFCP_IEI_FRAMED_IPV6_ROUTE, "Framed-IPv6-Route" },
	{ OSMO_PFCP_IEI_TIME_STAMP, "Time Stamp" },
	{ OSMO_PFCP_IEI_AVERAGING_WINDOW, "Averaging Window" },
	{ OSMO_PFCP_IEI_PAGING_POLICY_INDICATOR, "Paging Policy Indicator" },
	{ OSMO_PFCP_IEI_APN_DNN, "APN/DNN" },
	{ OSMO_PFCP_IEI_3GPP_IFACE_TYPE, "3GPP Interface Type" },
	{ OSMO_PFCP_IEI_PFCPSRREQ_FLAGS, "PFCPSRReq-Flags" },
	{ OSMO_PFCP_IEI_PFCPAUREQ_FLAGS, "PFCPAUReq-Flags" },
	{ OSMO_PFCP_IEI_ACTIVATION_TIME, "Activation Time" },
	{ OSMO_PFCP_IEI_DEACTIVATION_TIME, "Deactivation Time" },
	{ OSMO_PFCP_IEI_CREATE_MAR, "Create MAR" },
	{ OSMO_PFCP_IEI_3GPP_ACCESS_FORW_ACTION_INFO, "3GPP Access Forwarding Action Information" },
	{ OSMO_PFCP_IEI_NON_3GPP_ACCESS_FORW_ACTION_INFO, "Non-3GPP Access Forwarding Action Information" },
	{ OSMO_PFCP_IEI_REMOVE_MAR, "Remove MAR" },
	{ OSMO_PFCP_IEI_UPD_MAR, "Update MAR" },
	{ OSMO_PFCP_IEI_MAR_ID, "MAR ID" },
	{ OSMO_PFCP_IEI_STEERING_FUNCTIONALITY, "Steering Functionality" },
	{ OSMO_PFCP_IEI_STEERING_MODE, "Steering Mode" },
	{ OSMO_PFCP_IEI_WEIGHT, "Weight" },
	{ OSMO_PFCP_IEI_PRIORITY, "Priority" },
	{ OSMO_PFCP_IEI_UPD_3GPP_ACCESS_FORW_ACTION_INFO, "Update 3GPP Access Forwarding Action Information" },
	{ OSMO_PFCP_IEI_UPD_NON_3GPP_ACCESS_FORW_ACTION_INFO, "Update Non 3GPP Access Forwarding Action Information" },
	{ OSMO_PFCP_IEI_UE_IP_ADDRESS_POOL_IDENTITY, "UE IP address Pool Identity" },
	{ OSMO_PFCP_IEI_ALTERNATIVE_SMF_IP_ADDRESS, "Alternative SMF IP Address" },
	{ OSMO_PFCP_IEI_PACKET_REPLICATION_AND_DETECTION_CARRY_ON_INFO, "Packet Replication and Detection Carry-On Information" },
	{ OSMO_PFCP_IEI_SMF_SET_ID, "SMF Set ID" },
	{ OSMO_PFCP_IEI_QUOTA_VALIDITY_TIME, "Quota Validity Time" },
	{ OSMO_PFCP_IEI_NUMBER_OF_REPS, "Number of Reports" },
	{ OSMO_PFCP_IEI_PFCP_SESS_RETENTION_INFO_IN_ASSOC_SETUP_REQ, "PFCP Session Retention Information (within PFCP Association Setup Request)" },
	{ OSMO_PFCP_IEI_PFCPASRSP_FLAGS, "PFCPASRsp-Flags" },
	{ OSMO_PFCP_IEI_CP_ENTITY_IP_ADDRESS, "CP PFCP Entity IP Address" },
	{ OSMO_PFCP_IEI_PFCPSEREQ_FLAGS, "PFCPSEReq-Flags" },
	{ OSMO_PFCP_IEI_USER_PLANE_PATH_RECOVERY_REP, "User Plane Path Recovery Report" },
	{ OSMO_PFCP_IEI_IP_MULTICAST_ADDR_INFO_IN_SESS_EST_REQ, "IP Multicast Addressing Info within PFCP Session Establishment Request" },
	{ OSMO_PFCP_IEI_JOIN_IP_MULTICAST_INFO_IE_IN_USAGE_REP, "Join IP Multicast Information IE within Usage Report" },
	{ OSMO_PFCP_IEI_LEAVE_IP_MULTICAST_INFO_IE_IN_USAGE_REP, "Leave IP Multicast Information IE within Usage Report" },
	{ OSMO_PFCP_IEI_IP_MULTICAST_ADDRESS, "IP Multicast Address" },
	{ OSMO_PFCP_IEI_SOURCE_IP_ADDRESS, "Source IP Address" },
	{ OSMO_PFCP_IEI_PACKET_RATE_STATUS, "Packet Rate Status" },
	{ OSMO_PFCP_IEI_CREATE_BRIDGE_INFO_FOR_TSC, "Create Bridge Info for TSC" },
	{ OSMO_PFCP_IEI_CREATED_BRIDGE_INFO_FOR_TSC, "Created Bridge Info for TSC" },
	{ OSMO_PFCP_IEI_DS_TT_PORT_NUMBER, "DS-TT Port Number" },
	{ OSMO_PFCP_IEI_NW_TT_PORT_NUMBER, "NW-TT Port Number" },
	{ OSMO_PFCP_IEI_TSN_BRIDGE_ID, "TSN Bridge ID" },
	{ OSMO_PFCP_IEI_TSC_MGMT_INFO_IE_IN_SESS_MOD_REQ, "TSC Management Information IE within PFCP Session Modification Request" },
	{ OSMO_PFCP_IEI_TSC_MGMT_INFO_IE_IN_SESS_MOD_RESP, "TSC Management Information IE within PFCP Session Modification Response" },
	{ OSMO_PFCP_IEI_TSC_MGMT_INFO_IE_IN_SESS_REP_REQ, "TSC Management Information IE within PFCP Session Report Request" },
	{ OSMO_PFCP_IEI_PORT_MGMT_INFO_CONTAINER, "Port Management Information Container" },
	{ OSMO_PFCP_IEI_CLOCK_DRIFT_CTRL_INFO, "Clock Drift Control Information" },
	{ OSMO_PFCP_IEI_REQUESTED_CLOCK_DRIFT_INFO, "Requested Clock Drift Information" },
	{ OSMO_PFCP_IEI_CLOCK_DRIFT_REP, "Clock Drift Report" },
	{ OSMO_PFCP_IEI_TSN_TIME_DOMAIN_NUMBER, "TSN Time Domain Number" },
	{ OSMO_PFCP_IEI_TIME_OFFSET_THRESH, "Time Offset Threshold" },
	{ OSMO_PFCP_IEI_CUMULATIVE_RATERATIO_THRESH, "Cumulative rateRatio Threshold" },
	{ OSMO_PFCP_IEI_TIME_OFFSET_MEAS, "Time Offset Measurement" },
	{ OSMO_PFCP_IEI_CUMULATIVE_RATERATIO_MEAS, "Cumulative rateRatio Measurement" },
	{ OSMO_PFCP_IEI_REMOVE_SRR, "Remove SRR" },
	{ OSMO_PFCP_IEI_CREATE_SRR, "Create SRR" },
	{ OSMO_PFCP_IEI_UPD_SRR, "Update SRR" },
	{ OSMO_PFCP_IEI_SESS_REP, "Session Report" },
	{ OSMO_PFCP_IEI_SRR_ID, "SRR ID" },
	{ OSMO_PFCP_IEI_ACCESS_AVAIL_CTRL_INFO, "Access Availability Control Information" },
	{ OSMO_PFCP_IEI_REQUESTED_ACCESS_AVAIL_INFO, "Requested Access Availability Information" },
	{ OSMO_PFCP_IEI_ACCESS_AVAIL_REP, "Access Availability Report" },
	{ OSMO_PFCP_IEI_ACCESS_AVAIL_INFO, "Access Availability Information" },
	{ OSMO_PFCP_IEI_PROVIDE_ATSSS_CTRL_INFO, "Provide ATSSS Control Information" },
	{ OSMO_PFCP_IEI_ATSSS_CTRL_PARAMS, "ATSSS Control Parameters" },
	{ OSMO_PFCP_IEI_MPTCP_CTRL_INFO, "MPTCP Control Information" },
	{ OSMO_PFCP_IEI_ATSSS_LL_CTRL_INFO, "ATSSS-LL Control Information" },
	{ OSMO_PFCP_IEI_PMF_CTRL_INFO, "PMF Control Information" },
	{ OSMO_PFCP_IEI_MPTCP_PARAMS, "MPTCP Parameters" },
	{ OSMO_PFCP_IEI_ATSSS_LL_PARAMS, "ATSSS-LL Parameters" },
	{ OSMO_PFCP_IEI_PMF_PARAMS, "PMF Parameters" },
	{ OSMO_PFCP_IEI_MPTCP_ADDRESS_INFO, "MPTCP Address Information" },
	{ OSMO_PFCP_IEI_UE_LINK_SPECIFIC_IP_ADDRESS, "UE Link-Specific IP Address" },
	{ OSMO_PFCP_IEI_PMF_ADDRESS_INFO, "PMF Address Information" },
	{ OSMO_PFCP_IEI_ATSSS_LL_INFO, "ATSSS-LL Information" },
	{ OSMO_PFCP_IEI_DATA_NETWORK_ACCESS_IDENTIFIER, "Data Network Access Identifier" },
	{ OSMO_PFCP_IEI_UE_IP_ADDRESS_POOL_INFO, "UE IP address Pool Information" },
	{ OSMO_PFCP_IEI_AVERAGE_PACKET_DELAY, "Average Packet Delay" },
	{ OSMO_PFCP_IEI_MIN_PACKET_DELAY, "Minimum Packet Delay" },
	{ OSMO_PFCP_IEI_MAX_PACKET_DELAY, "Maximum Packet Delay" },
	{ OSMO_PFCP_IEI_QOS_REP_TRIGGER, "QoS Report Trigger" },
	{ OSMO_PFCP_IEI_GTP_U_PATH_QOS_CTRL_INFO, "GTP-U Path QoS Control Information" },
	{ OSMO_PFCP_IEI_GTP_U_PATH_QOS_REP_NODE_REP_REQ, "GTP-U Path QoS Report (PFCP Node Report Request)" },
	{ OSMO_PFCP_IEI_QOS_INFO_IN_GTP_U_PATH_QOS_REP, "QoS Information in GTP-U Path QoS Report" },
	{ OSMO_PFCP_IEI_GTP_U_PATH_IFACE_TYPE, "GTP-U Path Interface Type" },
	{ OSMO_PFCP_IEI_QOS_MONITORING_PER_QOS_FLOW_CTRL_INFO, "QoS Monitoring per QoS flow Control Information" },
	{ OSMO_PFCP_IEI_REQUESTED_QOS_MONITORING, "Requested QoS Monitoring" },
	{ OSMO_PFCP_IEI_REPORTING_FREQUENCY, "Reporting Frequency" },
	{ OSMO_PFCP_IEI_PACKET_DELAY_THRESHOLDS, "Packet Delay Thresholds" },
	{ OSMO_PFCP_IEI_MIN_WAIT_TIME, "Minimum Wait Time" },
	{ OSMO_PFCP_IEI_QOS_MONITORING_REP, "QoS Monitoring Report" },
	{ OSMO_PFCP_IEI_QOS_MONITORING_MEAS, "QoS Monitoring Measurement" },
	{ OSMO_PFCP_IEI_MT_EDT_CTRL_INFO, "MT-EDT Control Information" },
	{ OSMO_PFCP_IEI_DL_DATA_PACKETS_SIZE, "DL Data Packets Size" },
	{ OSMO_PFCP_IEI_QER_CTRL_INDICATIONS, "QER Control Indications" },
	{ OSMO_PFCP_IEI_PACKET_RATE_STATUS_REP, "Packet Rate Status Report" },
	{ OSMO_PFCP_IEI_NF_INST_ID, "NF Instance ID" },
	{ OSMO_PFCP_IEI_ETHERNET_CONTEXT_INFO, "Ethernet Context Information" },
	{ OSMO_PFCP_IEI_REDUNDANT_TRANSMISSION_PARAMS, "Redundant Transmission Parameters" },
	{ OSMO_PFCP_IEI_UPDATED_PDR, "Updated PDR" },
	{ OSMO_PFCP_IEI_S_NSSAI, "S-NSSAI" },
	{ OSMO_PFCP_IEI_IP_VERSION, "IP version" },
	{ OSMO_PFCP_IEI_PFCPASREQ_FLAGS, "PFCPASReq-Flags" },
	{ OSMO_PFCP_IEI_DATA_STATUS, "Data Status" },
	{ OSMO_PFCP_IEI_PROVIDE_RDS_CONF_INFO, "Provide RDS configuration information" },
	{ OSMO_PFCP_IEI_RDS_CONF_INFO, "RDS configuration information" },
	{ OSMO_PFCP_IEI_QUERY_PACKET_RATE_STATUS_IE_IN_SESS_MOD_REQ, "Query Packet Rate Status IE within PFCP Session Modification Request" },
	{ OSMO_PFCP_IEI_PACKET_RATE_STATUS_REP_IE_IN_SESS_MOD_RESP, "Packet Rate Status Report IE within PFCP Session Modification Response" },
	{ OSMO_PFCP_IEI_MPTCP_APPLICABLE_IND, "MPTCP Applicable Indication" },
	{ OSMO_PFCP_IEI_BRIDGE_MGMT_INFO_CONTAINER, "Bridge Management Information Container" },
	{ OSMO_PFCP_IEI_UE_IP_ADDRESS_USAGE_INFO, "UE IP Address Usage Information" },
	{ OSMO_PFCP_IEI_NUMBER_OF_UE_IP_ADDRS, "Number of UE IP Addresses" },
	{ OSMO_PFCP_IEI_VALIDITY_TIMER, "Validity Timer" },
	{ OSMO_PFCP_IEI_REDUNDANT_TRANSMISSION_FORW_PARAMS, "Redundant Transmission Forwarding Parameters" },
	{ OSMO_PFCP_IEI_TRANSPORT_DELAY_REPORTING, "Transport Delay Reporting" },
	{ 0 }
};

const struct value_string osmo_pfcp_cause_strs[] = {
	{ OSMO_PFCP_CAUSE_RESERVED, "0" },
	{ OSMO_PFCP_CAUSE_REQUEST_ACCEPTED, "Request accepted (success)" },
	{ OSMO_PFCP_CAUSE_MORE_USAGE_REPORT_TO_SEND, "More Usage Report to send" },
	{ OSMO_PFCP_CAUSE_REQUEST_REJECTED, "Request rejected (reason not specified)" },
	{ OSMO_PFCP_CAUSE_SESSION_CTX_NOT_FOUND, "Session context not found" },
	{ OSMO_PFCP_CAUSE_MANDATORY_IE_MISSING, "Mandatory IE missing" },
	{ OSMO_PFCP_CAUSE_CONDITIONAL_IE_MISSING, "Conditional IE missing" },
	{ OSMO_PFCP_CAUSE_INVALID_LENGTH, "Invalid length" },
	{ OSMO_PFCP_CAUSE_MANDATORY_IE_INCORRECT, "Mandatory IE incorrect" },
	{ OSMO_PFCP_CAUSE_INVALID_FORW_POLICY, "Invalid Forwarding Policy" },
	{ OSMO_PFCP_CAUSE_INVALID_F_TEID_ALLOC_OPTION, "Invalid F-TEID allocation option" },
	{ OSMO_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOC, "No established PFCP Association" },
	{ OSMO_PFCP_CAUSE_RULE_CREATION_MOD_FAILURE, "Rule creation/modification Failure" },
	{ OSMO_PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION, "PFCP entity in congestion" },
	{ OSMO_PFCP_CAUSE_NO_RESOURCES_AVAILABLE, "No resources available" },
	{ OSMO_PFCP_CAUSE_SERVICE_NOT_SUPPORTED, "Service not supported" },
	{ OSMO_PFCP_CAUSE_SYSTEM_FAILURE, "System failure" },
	{ OSMO_PFCP_CAUSE_REDIRECTION_REQUESTED, "Redirection Requested" },
	{ OSMO_PFCP_CAUSE_ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED, "All dynamic addresses are occupied" },
	{ 0 }
};

const struct value_string osmo_pfcp_up_feature_strs[] = {
	{ OSMO_PFCP_UP_FEAT_BUCP, "BUCP" },
	{ OSMO_PFCP_UP_FEAT_DDND, "DDND" },
	{ OSMO_PFCP_UP_FEAT_DLBD, "DLBD" },
	{ OSMO_PFCP_UP_FEAT_TRST, "TRST" },
	{ OSMO_PFCP_UP_FEAT_FTUP, "FTUP" },
	{ OSMO_PFCP_UP_FEAT_PFDM, "PFDM" },
	{ OSMO_PFCP_UP_FEAT_HEEU, "HEEU" },
	{ OSMO_PFCP_UP_FEAT_TREU, "TREU" },
	{ OSMO_PFCP_UP_FEAT_EMPU, "EMPU" },
	{ OSMO_PFCP_UP_FEAT_PDIU, "PDIU" },
	{ OSMO_PFCP_UP_FEAT_UDBC, "UDBC" },
	{ OSMO_PFCP_UP_FEAT_QUOAC, "QUOAC" },
	{ OSMO_PFCP_UP_FEAT_TRACE, "TRACE" },
	{ OSMO_PFCP_UP_FEAT_FRRT, "FRRT" },
	{ OSMO_PFCP_UP_FEAT_PFDE, "PFDE" },
	{ OSMO_PFCP_UP_FEAT_EPFAR, "EPFAR" },
	{ OSMO_PFCP_UP_FEAT_DPDRA, "DPDRA" },
	{ OSMO_PFCP_UP_FEAT_ADPDP, "ADPDP" },
	{ OSMO_PFCP_UP_FEAT_UEIP, "UEIP" },
	{ OSMO_PFCP_UP_FEAT_SSET, "SSET" },
	{ OSMO_PFCP_UP_FEAT_MNOP, "MNOP" },
	{ OSMO_PFCP_UP_FEAT_MTE, "MTE" },
	{ OSMO_PFCP_UP_FEAT_BUNDL, "BUNDL" },
	{ OSMO_PFCP_UP_FEAT_GCOM, "GCOM" },
	{ OSMO_PFCP_UP_FEAT_MPAS, "MPAS" },
	{ OSMO_PFCP_UP_FEAT_RTTL, "RTTL" },
	{ OSMO_PFCP_UP_FEAT_VTIME, "VTIME" },
	{ OSMO_PFCP_UP_FEAT_NORP, "NORP" },
	{ OSMO_PFCP_UP_FEAT_IP6PL, "IP6PL" },
	{ OSMO_PFCP_UP_FEAT_TSCU, "TSCU" },
	{ OSMO_PFCP_UP_FEAT_MPTCP, "MPTCP" },
	{ OSMO_PFCP_UP_FEAT_ATSSSLL, "ATSSSLL" },
	{ OSMO_PFCP_UP_FEAT_QFQM, "QFQM" },
	{ OSMO_PFCP_UP_FEAT_GPQM, "GPQM" },
	{ OSMO_PFCP_UP_FEAT_MTEDT, "MTEDT" },
	{ OSMO_PFCP_UP_FEAT_CIOT, "CIOT" },
	{ OSMO_PFCP_UP_FEAT_ETHAR, "ETHAR" },
	{ OSMO_PFCP_UP_FEAT_DDDS, "DDDS" },
	{ OSMO_PFCP_UP_FEAT_RDS, "RDS" },
	{ OSMO_PFCP_UP_FEAT_RTTWP, "RTTWP" },
	{}
};


const struct value_string osmo_pfcp_cp_feature_strs[] = {
	{ OSMO_PFCP_CP_FEAT_LOAD, "LOAD" },
	{ OSMO_PFCP_CP_FEAT_OVRL, "OVRL" },
	{ OSMO_PFCP_CP_FEAT_EPFAR, "EPFAR" },
	{ OSMO_PFCP_CP_FEAT_SSET, "SSET" },
	{ OSMO_PFCP_CP_FEAT_BUNDL, "BUNDL" },
	{ OSMO_PFCP_CP_FEAT_MPAS, "MPAS" },
	{ OSMO_PFCP_CP_FEAT_ARDR, "ARDR" },
	{ OSMO_PFCP_CP_FEAT_UIAUR, "UIAUR" },
	{}
};

const struct value_string osmo_pfcp_apply_action_strs[] = {
	{ OSMO_PFCP_APPLY_ACTION_DROP, "DROP" },
	{ OSMO_PFCP_APPLY_ACTION_FORW, "FORW" },
	{ OSMO_PFCP_APPLY_ACTION_BUFF, "BUFF" },
	{ OSMO_PFCP_APPLY_ACTION_NOCP, "NOCP" },
	{ OSMO_PFCP_APPLY_ACTION_DUPL, "DUPL" },
	{ OSMO_PFCP_APPLY_ACTION_IPMA, "IPMA" },
	{ OSMO_PFCP_APPLY_ACTION_IPMD, "IPMD" },
	{ OSMO_PFCP_APPLY_ACTION_DFRT, "DFRT" },
	{ OSMO_PFCP_APPLY_ACTION_EDRT, "EDRT" },
	{ OSMO_PFCP_APPLY_ACTION_BDPN, "BDPN" },
	{ OSMO_PFCP_APPLY_ACTION_DDPN, "DDPN" },
	{}
};

const struct value_string osmo_pfcp_outer_header_creation_strs[] = {
	{ OSMO_PFCP_OUTER_HEADER_CREATION_GTP_U_UDP_IPV4, "GTP_U_UDP_IPV4" },
	{ OSMO_PFCP_OUTER_HEADER_CREATION_GTP_U_UDP_IPV6, "GTP_U_UDP_IPV6" },
	{ OSMO_PFCP_OUTER_HEADER_CREATION_UDP_IPV4, "UDP_IPV4" },
	{ OSMO_PFCP_OUTER_HEADER_CREATION_UDP_IPV6, "UDP_IPV6" },
	{ OSMO_PFCP_OUTER_HEADER_CREATION_IPV4, "IPV4" },
	{ OSMO_PFCP_OUTER_HEADER_CREATION_IPV6, "IPV6" },
	{ OSMO_PFCP_OUTER_HEADER_CREATION_C_TAG, "C_TAG" },
	{ OSMO_PFCP_OUTER_HEADER_CREATION_S_TAG, "S_TAG" },
	{ OSMO_PFCP_OUTER_HEADER_CREATION_N19_INDICATION, "N19_INDICATION" },
	{ OSMO_PFCP_OUTER_HEADER_CREATION_N6_INDICATION, "N6_INDICATION" },
	{}
};

const struct value_string osmo_pfcp_outer_header_removal_desc_strs[] = {
	{ OSMO_PFCP_OUTER_HEADER_REMOVAL_GTP_U_UDP_IPV4, "GTP_U_UDP_IPV4" },
	{ OSMO_PFCP_OUTER_HEADER_REMOVAL_GTP_U_UDP_IPV6, "GTP_U_UDP_IPV6" },
	{ OSMO_PFCP_OUTER_HEADER_REMOVAL_UDP_IPV4, "UDP_IPV4" },
	{ OSMO_PFCP_OUTER_HEADER_REMOVAL_UDP_IPV6, "UDP_IPV6" },
	{ OSMO_PFCP_OUTER_HEADER_REMOVAL_IPV4, "IPV4" },
	{ OSMO_PFCP_OUTER_HEADER_REMOVAL_IPV6, "IPV6" },
	{ OSMO_PFCP_OUTER_HEADER_REMOVAL_GTP_U_UDP_IP, "GTP_U_UDP_IP" },
	{ OSMO_PFCP_OUTER_HEADER_REMOVAL_VLAN_S_TAG, "VLAN_S_TAG" },
	{ OSMO_PFCP_OUTER_HEADER_REMOVAL_S_TAG_AND_C_TAG, "S_TAG_AND_C_TAG" },
	{}
};

const struct value_string osmo_pfcp_source_iface_strs[] = {
	{ OSMO_PFCP_SOURCE_IFACE_ACCESS, "Access" },
	{ OSMO_PFCP_SOURCE_IFACE_CORE, "Core" },
	{ OSMO_PFCP_SOURCE_IFACE_SGI_LAN_N6_LAN, "SGi-LAN/N6-LAN" },
	{ OSMO_PFCP_SOURCE_IFACE_CP_FUNCTION, "CP-function" },
	{ OSMO_PFCP_SOURCE_IFACE_5G_VN_INTERNAL, "5G-VN-Internal" },
	{}
};

const struct value_string osmo_pfcp_dest_iface_strs[] = {
	{ OSMO_PFCP_DEST_IFACE_ACCESS, "Access" },
	{ OSMO_PFCP_DEST_IFACE_CORE, "Core" },
	{ OSMO_PFCP_DEST_IFACE_SGI_LAN_N6_LAN, "SGi-LAN/N6-LAN" },
	{ OSMO_PFCP_DEST_IFACE_CP_FUNCTION, "CP-function" },
	{ OSMO_PFCP_DEST_IFACE_LI_FUNCTION, "LI-function" },
	{ OSMO_PFCP_DEST_IFACE_5G_VN_INTERNAL, "5G-VN-Internal" },
	{}
};

const struct value_string osmo_pfcp_3gpp_iface_type_strs[] = {
	{ OSMO_PFCP_3GPP_IFACE_TYPE_S1_U, "S1_U" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_S5_S8_U, "S5_S8_U" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_S4_U, "S4_U" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_S11_U, "S11_U" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_S12_U, "S12_U" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_GN_GP_U, "GN_GP_U" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_S2A_U, "S2A_U" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_S2B_U, "S2B_U" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_ENODEB_GTP_U_INTERFACE_FOR_DL_DATA_FORWARDING, "ENODEB_GTP_U_INTERFACE_FOR_DL_DATA_FORWARDING" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_ENODEB_GTP_U_INTERFACE_FOR_UL_DATA_FORWARDING, "ENODEB_GTP_U_INTERFACE_FOR_UL_DATA_FORWARDING" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_SGW_UPF_GTP_U_INTERFACE_FOR_DL_DATA_FORWARDING, "SGW_UPF_GTP_U_INTERFACE_FOR_DL_DATA_FORWARDING" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_N3_3GPP_ACCESS, "N3_3GPP_ACCESS" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_N3_TRUSTED_NON_3GPP_ACCESS, "N3_TRUSTED_NON_3GPP_ACCESS" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_N3_UNTRUSTED_NON_3GPP_ACCESS, "N3_UNTRUSTED_NON_3GPP_ACCESS" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_N3_FOR_DATA_FORWARDING, "N3_FOR_DATA_FORWARDING" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_N9, "N9" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_SGI, "SGI" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_N6, "N6" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_N19, "N19" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_S8_U, "S8_U" },
	{ OSMO_PFCP_3GPP_IFACE_TYPE_GP_U, "GP_U" },
	{}
};
