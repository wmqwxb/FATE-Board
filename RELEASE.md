# Release 1.11.1

#### Major Features and Improvements
**Major Features**

* Optimize authentication mechanism for websocket.
* Optimize page rendering

# Release 1.11.0

#### Major Features and Improvements
**Major Features**

* Binning component display optimization
* Password configuration item allows encryption

# Release 1.10.0

#### Major Features and Improvements
**Major Features**

* Display SBT leaf node data
* Support result summary display for Sampler's new method 
* Add model summary for new module Positive Unlabeled Learning
* Improved table display for Binning
* Data filtering on requested model proto
* Adjusted Design
* Improved Logging display adaptation

# Release 1.9.1

#### Major Features and Improvements
**Major Features**

* Fix the problem that the graph shows the mismatch after the binning component detail data is loaded
* Repair DAG diagram component port display defect

# Release 1.9.0

#### Major Features and Improvements
**Major Features**

* Add feature number limitation when displaying Pearson component correlation  graph to ensure interactive friendliness
* Update the login encryption method to reduce the risk caused by the time synchronization between the browser and the server
* psi, pearson, data statistic and other components are open to download data
* Feature Anonymous Showcase Upgrade
* High availability display support
* Revised and updated display details
* Rendering component module finishing optimization
* Differentiated rendering for task components with large amounts of data


# Relaese 1.8.0.1
#### Major Features and Improvements
**Major Features**

* Fast JSON version update
* Spring version update
* Code update because of dependent upgrade


# Release 1.8.0

#### Major Features and Improvements
**Major Features**

* Support GBDTMO mode for Secureboost
* Add SSHE Linr component
* Add Writer component
* Delete data-output port for data-statistic compoent
* Fix display bug and optimize transport protocal support


# Release 1.7.2.2

#### Major Features and Improvements
**Major Features**

* Detail finalization and Configuration calibration


# Release 1.7.2.1

#### Major Features and Improvements
**Major Features**

* Update shelljs from 0.8.3 to 0.8.5
* Update spring-core from 5.2.9Release to 5.3.14


# Release 1.7.2

#### Major Features and Improvements
**Major Features**

* Confusion matrix data display upgrade
* Component port bug fixed
* No data prompt upgrade


# Release 1.7.1

#### Major Features and Improvements
**Major Features**

* Disable password storage to avoid security problem
* Update DOM structure for login-form


# Release 1.7.0

#### Major Features and Improvements
**Major Features**

* Add new components
* Components display optimization
* Hetero binning supports multi-category display
* Embodiment of warm start mechanism
* Interaction optimization

# Release 1.6.1

#### Major Features and Improvements
**Major Features**

* Support HTTPS protocol
* Scientific notation display optimization
* Anonymous display optimization
* Fix routing issues

# Release 1.6.0

#### Major Features and Improvements

* SBT Transformer: new module, encode features using Hetero SBT model
* Sample Weight: new module, set sample weights based on label or from feature column 
* Homo Feature Binning: new module, performs homogeneous federated binning, bin number and bin interval available on Board 
* Data Transformer: new module, same functionality as DataIO with added features such as case-insensitive 
* Reader: supports image format input 
* Hetero Feature Binning: filter results display by WOE
* Hetero Pearson: support VIF computation 
* Feature Selection: support selection based on VIF 
* SecureBoost: display gain & split simultaneously; Performance Score diagram for binary classification 
* Cross Validation: display & download fold split history and fold prediction results
* Evaluation: metrics & visualization for each one_vs_rest child model 
* Export job DSL & Conf files on Board 
* Search for jobs using party_id 
* Improved component model/data download 
* Improved performance score display over large number of iterations or cv folds

# Release 1.5.3

#### Major Features and Improvements
**Major Features**

- Fix feature anonym inconsistency of HeteroBinning
- Login page memorizes default account(admin) and password(admin)

# Release 1.5.2

#### Major Features and Improvements
**Major Features**

- Update for security 
- Add default login account (Account:admin  Password:admin)


# Release 1.5.1

#### Major Features and Improvements
**Major Features**

- Modify the display of DAG diagram 


# Release 1.5.0

#### Major Features and Improvements
**Major Features**

- Add model visualization of new algorithm components：Hetero/Homo Data Split, Table reader, Data Statistic, PSI，Hetero Fastsecureboost，Hetero Kmeans
  - Hetero/Homo Data Split：Visualize dataset split results (training/validate/test)
  - Table reader：read in the original modeling data and output data overview
  - Data Statistic：display statistical indicators of each variable
  - PSI：PSI detailed data display for each variable
  - Hetero Fastsecureboost：fast secureboost model visualization in layered-mode and mixed-mode
  - Hetero Kmeans：visualization of sample clustering results
- Feature selection：supports connection with the output models of Data Statistic, PSI, SecureBoost, and other components for feature selection
- Feature binning：Support binning visualization without calculating the iv value, and increase the display of the number of bins
- Evaluation：Supports visualization of cluster model evaluation results
- Hetero secureboost：Supports visualization of Completely SecureBoost models
- Evaluation：Supports visualization of cluster model evaluation results
- Support downloading model and data of algorithm components from FATEBoard（Feature Binning，Feature Selection，Secureboost，LR，Evaluation）
- The page supports partial data refresh and global data refresh to update the data in the iteration
- Support retry for failed or canceled job
- Data input port of the component supports separate access according to train/validate
- Make the status of job compatible for success and complete

**Features improvement**

- Job list optimization：search, filter, and sort optimization
- Significantly improve page fluency when the amount of data is large
- Optimize the log pull method and improve efficiency
- Enhance safety check
- Interface optimization
- Data decoupling：separate the relationship between presentation, interaction, and data of the page
- Interaction logic decoupling：Disassembly and refinement of complex functional logic
- Improve the cohesion and reusability of components and tools

# Release 1.4.2

#### Major Features and Improvements
- Pearson support unilateraly operation
- Selection support sorting
- Add field search function for job-list
- Add fateflow dispatch log in dashboard
- Optimize some forms of interaction


# Release 1.4.1

#### Major Features and Improvements
- Support PSI display in evaluation component
- Support confusion matrix display
- Update logs interface
- Firefox basic compatibility
# Release 1.4.0

#### Major Features and Improvements
- Add security check for file path of logs
- Pearson correlation：support drawing a matrix graph by selecting different roles or features, or by interval filtering of correlation values. support sorting by the size of the correlation value.
- Homo secureboost: new visualization of model ouput，including trees，feature importance、cross validation，etc.
- GLM-stepwise：new visualization of stepwise from hetero LR，hetero LinLR and hetero poisson, including Model Fitting Statistics, Analysis of Effects, Analysis of Maximum Likelihood Estimates, and Analysis of Effect Eligible for Entry for each step, as well as for the summary.
- Hetero LR, localbaseline: new visualization of one_vs_rest.
- Show the best iteration version in model output.

# Release 1.3.1

#### Major Features and Improvements
- Support the plugins


# Release 1.3.0

#### Major Features and Improvements
- Fix the bug of getting logs


# Release 1.2.0

#### Major Features and Improvements

New components:  

- Heterogeneous feature correlation component: visualizing the correlation matrix  diagram，filtering by role or variable, and scaling of diagram  
- Upload component: uploading data, and supporting for viewing data output
- Download component: downloading data, and supporting for viewing data output 
- LocalBaseline component: A LR component based on Sklearn run to compare the performance  of Federated LR 

Component optimization：

- Secureboost: Visual enhancement of secureboost tree diagrams, and support for scaling  and dragging trees 

- Federated Sample: Filtering by label to display the table content 

- Model output of some components supports global fuzzy search
- Model output of some components supports for table column sorting 
- Model output of some components supports multi-host visualization and filtering by role,  and adds variable mapping 
- Optimize cross-validation curves and loss curves  support visualization and interaction  of  large data volumes, and support for manual refresh during operation 

Others:

- Job detail page redesign, and support for workflow scaling and dragging, and optimize  parameter  display 
- Add job note and support for description and classification 
- Log load optimization 
  



# Release 1.1.1

#### Major Features and Improvements

- Support the visual tree models of secureboost

- Support the visualization for heterogeneous LinearRegression

- Support the visualization for homogeneous Deep Neural Network

- Support to view all component parameters

- Support separation of data ports and model ports in all the components

- Support visualization of evaluation results during training

- Support for job queries, filters, and list sorting

- Optimize the visual outputs of feature selection,feature binning,etc

- Optimize dashboard and workflow visualization,and support workflow scaling

# Release 1.1

#### Major Features and Improvements

- Support the visual tree models of secureboost
- Support the visualization for heterogeneous LinearRegression
- Support the visualization for homogeneous Deep Neural Network
- Support to view all component parameters
- Support separation of data ports and model ports in all the components
- Support visualization of evaluation results during training
- Support for job queries, filters, and list sorting
- Optimize the visual outputs of feature selection,feature binning,etc
- Optimize dashboard and workflow visualization,and support workflow scaling




# Release 1.0.2

#### Major Features and Improvements

- Support  various ways for searching job
  
  

# Release 1.0.1

#### Bug Fixes

- Fix the display problems 
  
  

# Release 1.0

#### Major Features and Improvements

This version includes one new product of FATE:FATE-Board. FATE-Board as a visual tool for federation modeling. 

- Federated Learning Job DashBoard
- Federated Learning Job Visualisation
- Federated Learning Job Management
- Real-time Log Panel
