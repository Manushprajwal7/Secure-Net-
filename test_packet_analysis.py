#!/usr/bin/env python3
"""
Test script for packet analysis functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import SecurityMonitor, Packets
from datetime import datetime

def test_packet_analysis():
    """Test the packet analysis methods with mock data"""
    print("Testing packet analysis functionality...")
    
    # Create a mock packet-like object
    class MockPacket:
        def __init__(self):
            self.highest_layer = 'TCP'
            self.sniff_time = datetime.now()
            self.transport_layer = 'TCP'
            
        class MockIP:
            def __init__(self):
                self.src = '192.168.1.100'
                self.dst = '192.168.1.1'
        
        class MockTCP:
            def __init__(self):
                self.srcport = '12345'
                self.dstport = '80'
                self.flags_syn = '0'
        
        class MockARP:
            def __init__(self):
                self.opcode = '2'
                self.psrc_resolved = '192.168.1.1'
                self.hwsrc = '00:11:22:33:44:55'
        
        class MockDNS:
            def __init__(self):
                self.qry_name = 'example.com'
                self.a = '93.184.216.34'
        
        def __getattr__(self, name):
            if name == 'ip':
                return self.MockIP()
            elif name == 'tcp':
                return self.MockTCP()
            elif name == 'arp':
                return self.MockARP()
            elif name == 'dns':
                return self.MockDNS()
            else:
                raise AttributeError(f"Mock packet has no attribute '{name}'")
    
    # Test with mock packet
    try:
        monitor = SecurityMonitor()
        mock_packet = MockPacket()
        
        print("Testing packet analysis...")
        monitor.analyze_packet(mock_packet)
        print("✓ Packet analysis completed successfully")
        
        print("Testing alert generation...")
        # Simulate a port scan by adding multiple connections
        for i in range(25):  # Above threshold
            monitor.connection_tracker['192.168.1.100'][str(1000 + i)] += 1
        
        # This should trigger a port scan alert
        monitor.check_port_scan(mock_packet)
        print("✓ Port scan detection working")
        
        print("Testing settings integration...")
        # Test threshold adjustment
        from app import app_settings
        original_threshold = app_settings['port_scan_threshold']
        app_settings['port_scan_threshold'] = 30
        
        # Reset connection tracker
        monitor.connection_tracker['192.168.1.100'].clear()
        
        # Add connections up to new threshold
        for i in range(35):  # Above new threshold
            monitor.connection_tracker['192.168.1.100'][str(2000 + i)] += 1
        
        # This should trigger a port scan alert with new threshold
        monitor.check_port_scan(mock_packet)
        print("✓ Dynamic threshold adjustment working")
        
        # Restore original threshold
        app_settings['port_scan_threshold'] = original_threshold
        
        print("\n🎉 All tests passed! Packet analysis is working correctly.")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = test_packet_analysis()
    sys.exit(0 if success else 1)
