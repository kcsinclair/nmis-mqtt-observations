#
#  Copyright (C) Opmantek Limited (www.opmantek.com)
#
#  This file is part of Network Management Information System ("NMIS").
#
#  NMIS is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  NMIS is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with NMIS (most likely in a file named LICENSE).
#  If not, see <http://www.gnu.org/licenses/>
#
# *****************************************************************************
#
# An NMIS collect plugin that publishes per-node latest_data observations
# to an MQTT broker as JSON messages, one message per inventory instance.
#
# Topic format:  {base_topic}/{node_name}/{concept}/{index}
# Config file:   conf/mqttobservations.nmis
# Install to:    conf/plugins/mqttobservations.pm
#
# Requires: Net::MQTT::Simple (cpanm Net::MQTT::Simple)
#
package mqttobservations;
our $VERSION = "1.0.0";

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../../lib";

use JSON::XS;
use NMISNG;
use NMISNG::Util;


# Maps concept names to the inventory data fields that best describe an instance.
# The first defined, non-empty field found is used.
my %DESCRIPTION_FIELDS = (
	'interface'        => [qw(ifDescr Description)],
	'catchall'         => [qw(sysDescr sysName nodeType)],
	'Host_Storage'     => [qw(hrStorageDescr)],
	'Host_File_System' => [qw(hrFSMountPoint hrFSType)],
	'Host_Partition'   => [qw(hrPartitionLabel hrPartitionID)],
	'entityMib'        => [qw(entPhysicalName entPhysicalDescr)],
	'cdp'              => [qw(cdpCacheDeviceId cdpCacheDevicePort)],
	'lldp'             => [qw(lldpRemSysName lldpRemPortDesc)],
	'bgp'              => [qw(bgpPeerIdentifier)],
	'vlan'             => [qw(vlanName vtpVlanName)],
	'mpls'             => [qw(mplsVpnVrfName)],
	'cbqos'            => [qw(CbQosPolicyMapName)],
	'addressTable'     => [qw(dot1dTpFdbAddress)],
);

# Fallback field names tried in order when concept is not in the map above.
my @FALLBACK_DESCRIPTION_FIELDS = qw(Description description Name name ifDescr);

sub collect_plugin
{
	my (%args) = @_;
	my ($node, $S, $C, $NG) = @args{qw(node sys config nmisng)};

	# Skip if node or SNMP is down — no fresh data to publish
	my ($catchall_inventory, $error) = $S->inventory(concept => 'catchall');
	if ($error)
	{
		$NG->log->error("MqttObservations: Failed to get catchall inventory for $node: $error");
		return (2, "Failed to get catchall inventory: $error");
	}

	my $catchall_data = $catchall_inventory->data();

	if (NMISNG::Util::getbool($catchall_data->{nodedown}))
	{
		$NG->log->debug("MqttObservations: Skipping $node — Node Down");
		return (0, undef);
	}
	if (NMISNG::Util::getbool($catchall_data->{snmpdown}))
	{
		$NG->log->debug("MqttObservations: Skipping $node — SNMP Down");
		return (0, undef);
	}

	# Load plugin configuration
	my $plugin_config = NMISNG::Util::loadTable(dir => 'conf', name => 'mqttobservations', conf => $C);
	if (!$plugin_config || ref($plugin_config) ne 'HASH')
	{
		$NG->log->error("MqttObservations: Failed to load conf/mqttobservations.nmis");
		return (2, "Failed to load mqttobservations config");
	}

	my $mqtt_config  = $plugin_config->{mqtt};
	my $concept_list = $plugin_config->{concepts};

	if (!$mqtt_config || !$mqtt_config->{server})
	{
		$NG->log->error("MqttObservations: No MQTT server configured in mqttobservations.nmis");
		return (2, "No MQTT server configured");
	}

	if (!$concept_list || !@$concept_list)
	{
		$NG->log->debug("MqttObservations: No concepts configured — skipping $node");
		return (0, undef);
	}

	my $extra_logging = NMISNG::Util::getbool($mqtt_config->{extra_logging});
	my $retain        = NMISNG::Util::getbool($mqtt_config->{retain});
	my $retries       = int($mqtt_config->{retries} // 1);
	my $base_topic    = $mqtt_config->{topic} // 'obs/nmis';

	# Build the node-level metadata envelope included in every message
	my $node_uuid = $S->nmisng_node->uuid() // '';
	my %node_meta = (
		node_name => $node,
		node_uuid => $node_uuid,
		group     => $catchall_data->{group}    // '',
		sysName   => $catchall_data->{sysName}  // '',
		host      => $catchall_data->{host}     // '',
		nodeType  => $catchall_data->{nodeType} // '',
	);

	my $json_encoder = JSON::XS->new->utf8->canonical;

	# Process each configured concept
	for my $concept (@$concept_list)
	{
		$NG->log->debug("MqttObservations: Processing concept '$concept' for $node")
			if $extra_logging;

		my $ids = $S->nmisng_node->get_inventory_ids(
			concept => $concept,
			filter  => {historic => 0},
		);

		if (!@$ids)
		{
			$NG->log->debug("MqttObservations: No inventory for '$concept' on $node")
				if $extra_logging;
			next;
		}

		for my $inv_id (@$ids)
		{
			my ($inventory, $error) = $S->nmisng_node->inventory(_id => $inv_id);
			if ($error)
			{
				$NG->log->warn("MqttObservations: Failed to get inventory $inv_id for '$concept' on $node: $error");
				next;
			}

			my $inv_data = $inventory->data();

			# Get latest data for this inventory instance (reads from latest_data collection)
			my $latest = $inventory->get_newest_timed_data();
			if (!$latest->{success} || !$latest->{data})
			{
				$NG->log->debug("MqttObservations: No latest data for '$concept' instance on $node"
					. ($latest->{error} ? ": $latest->{error}" : ''))
					if $extra_logging;
				next;
			}

			# Determine the index: use the inventory data's index field, fall back to '0'
			my $index = $inv_data->{index} // '0';

			# Sanitize index for use as an MQTT topic component
			my $topic_index = $index;
			$topic_index =~ s|/|_|g;
			$topic_index =~ s/\s+/_/g;

			# Determine the best human-readable description for this instance
			my $description = _get_description($concept, $inv_data);

			# Build a list of messages to publish.
			# For catchall, split into one message per subconcept (health, tcp, laload, etc.)
			# For other concepts, publish one message per inventory instance as before.
			my @messages;

			if ($concept eq 'catchall')
			{
				for my $subconcept (sort keys %{$latest->{data}})
				{
					my $sub_data = $latest->{data}{$subconcept};
					next if (!$sub_data || ref($sub_data) ne 'HASH');

					my $sub_derived = _filter_derived($latest->{derived_data}{$subconcept});

					push @messages, {
						topic   => "$base_topic/$node/$subconcept/$topic_index",
						payload => {
							%node_meta,
							concept      => $concept,
							subconcept   => $subconcept,
							index        => $index,
							description  => $description,
							timestamp    => $latest->{time} // time(),
							data         => $sub_data,
							derived_data => (%$sub_derived ? $sub_derived : undef),
						},
					};
				}
			}
			else
			{
				# Filter derived_data: exclude keys beginning with "08" or "16"
				my %filtered_derived;
				if ($latest->{derived_data})
				{
					for my $subconcept (keys %{$latest->{derived_data}})
					{
						my $filtered = _filter_derived($latest->{derived_data}{$subconcept});
						$filtered_derived{$subconcept} = $filtered if %$filtered;
					}
				}

				push @messages, {
					topic   => "$base_topic/$node/$concept/$topic_index",
					payload => {
						%node_meta,
						concept      => $concept,
						index        => $index,
						description  => $description,
						timestamp    => $latest->{time} // time(),
						data         => $latest->{data},
						derived_data => (%filtered_derived ? \%filtered_derived : undef),
					},
				};
			}

			for my $msg (@messages)
			{
				$NG->log->debug("MqttObservations: Publishing to $msg->{topic}") if $extra_logging;

				my $encoded = $json_encoder->encode($msg->{payload});
				my $pub_error = publishMqtt(
					topic    => $msg->{topic},
					message  => $encoded,
					retain   => $retain,
					retries  => $retries,
					server   => $mqtt_config->{server},
					username => $mqtt_config->{username},
					password => $mqtt_config->{password},
				);
				if ($pub_error)
				{
					$NG->log->error("MqttObservations: Failed to publish to $msg->{topic}: $pub_error");
				}
			}
		}
	}

	return (0, undef);    # We publish externally; no NMIS node data was modified
}

# Filter a single derived_data hash: exclude keys beginning with "08" or "16"
# args: hashref (may be undef)
# returns: hashref (possibly empty)
sub _filter_derived
{
	my ($src) = @_;
	return {} if (!$src || ref($src) ne 'HASH');
	my %filtered = map { $_ => $src->{$_} }
		grep { $_ !~ /^(?:08|16)/ } keys %$src;
	return \%filtered;
}

# Return the best description string for an inventory instance.
# Tries concept-specific field names first, then generic fallbacks.
sub _get_description
{
	my ($concept, $data) = @_;

	my @fields = @{$DESCRIPTION_FIELDS{$concept} // []};
	push @fields, @FALLBACK_DESCRIPTION_FIELDS;

	for my $field (@fields)
	{
		return $data->{$field}
			if defined $data->{$field} && $data->{$field} ne '';
	}
	return '';
}

sub publishMqtt {
	my %arg = @_;
	my $topic = $arg{topic};
	my $message = $arg{message};
	my $retain = $arg{retain};
	my $retries = int($arg{retries} // 1);
	my $server = $arg{server};
	my $username = $arg{username};
	my $password = $arg{password};

	$ENV{MQTT_SIMPLE_ALLOW_INSECURE_LOGIN} = 1;

	my $last_error;
	for my $attempt (0 .. $retries)
	{
		eval {
			my $mqtt = Net::MQTT::Simple->new($server);
			$mqtt->login($username,$password);

			if ( $retain ) {
				$mqtt->retain($topic => $message);
			}
			else {
				$mqtt->publish($topic => $message);
			}
		};
		if ($@) {
			$last_error = $@;
			next;
		}
		return undef;    # success
	}
	return $last_error;
}

1;
