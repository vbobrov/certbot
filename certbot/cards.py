csrCardJson="""
{
    "type": "AdaptiveCard",
    "version": "1.0",
    "body": [
        {
            "type": "TextBlock",
            "text": "Enter Request Information",
            "size": "Large",
            "weight": "Bolder"
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Common Name (CN)",
                            "id": ""
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.Text",
                            "placeholder": "www.example.com",
                            "id": "CN"
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "E-Mail Address (E)",
                            "id": ""
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.Text",
                            "placeholder": "john@example.com",
                            "id": "E"
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Organizational Unit (OU)",
                            "id": ""
                        },
                        {
                            "type": "TextBlock",
                            "text": "Comma-Separated",
                            "id": "",
                            "spacing": "None"
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.Text",
                            "placeholder": "IT,Security",
                            "id": "OU"
                        }
                    ],
                    "verticalContentAlignment": "Center"
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Domain Component (DC)",
                            "id": ""
                        },
                        {
                            "type": "TextBlock",
                            "text": "Comma-Separated",
                            "id": "",
                            "spacing": "None"
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.Text",
                            "placeholder": "example,com",
                            "id": "DC"
                        }
                    ],
                    "verticalContentAlignment": "Center"
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Organization (O)",
                            "id": ""
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.Text",
                            "placeholder": "Example Corp",
                            "id": "O"
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Locality/City (L)",
                            "id": ""
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.Text",
                            "placeholder": "New York",
                            "id": "L"
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "State (ST)",
                            "id": ""
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.Text",
                            "placeholder": "NY",
                            "id": "ST"
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Country (C)",
                            "id": ""
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.Text",
                            "placeholder": "US",
                            "id": "C"
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Subject Alt Name (SAN)",
                            "id": ""
                        },
                        {
                            "type": "TextBlock",
                            "text": "Comma-Separated",
                            "id": "",
                            "spacing": "Small"
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.Text",
                            "placeholder": "www.example.com,1.2.3.4",
                            "id": "SAN"
                        }
                    ],
                    "verticalContentAlignment": "Center"
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Key Size",
                            "id": ""
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.ChoiceSet",
                            "placeholder": "Select Key Size",
                            "choices": [
                                {
                                    "title": "2048",
                                    "value": "2048"
                                },
                                {
                                    "title": "4096",
                                    "value": "4096"
                                }
                            ],
                            "value": "2048",
                            "id": "KeySize"
                        }
                    ]
                }
            ]
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": "Key Usage",
                            "id": ""
                        }
                    ]
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "Input.ChoiceSet",
                            "placeholder": "",
                            "choices": [
                                {
                                    "title": "Server Auth",
                                    "value": "ServerAuth"
                                },
                                {
                                    "title": "Client Auth",
                                    "value": "ClientAuth"
                                }
                            ],
                            "isMultiSelect": true,
                            "id": "KeyUsage",
                            "style": "expanded",
                            "value": "ServerAuth,ClientAuth"
                        }
                    ]
                }
            ]
        },
        {
            "type": "ActionSet",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Generate CSR"
                }
            ]
        }
    ],
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json"
}
"""