use std::any::Any;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use async_trait::async_trait;
use datafusion::arrow::array::{ArrayBuilder, StringBuilder, UInt32Builder};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::{TableProvider, TableType};
use datafusion::error::Result;
use datafusion::execution::context::{SessionState, TaskContext};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionMode, ExecutionPlan, Partitioning,
    PlanProperties, project_schema, SendableRecordBatchStream,
};
use datafusion::physical_plan::memory::MemoryStream;
use datafusion::prelude::*;
use datafusion_common::DataFusionError;
use datafusion_physical_expr::EquivalenceProperties;

#[derive(Debug, Clone)]
struct PasswdEntry {
    username: String,
    password: String,
    uid: u32,
    gid: u32,
    description: String,
    home_directory: String,
    shell: String,
}

impl PasswdEntry {
    fn from_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 7 {
            return None;
        }
        Some(PasswdEntry {
            username: parts[0].to_string(),
            password: parts[1].to_string(),
            uid: parts[2].parse().ok()?,
            gid: parts[3].parse().ok()?,
            description: parts[4].to_string(),
            home_directory: parts[5].to_string(),
            shell: parts[6].to_string(),
        })
    }
}

fn read_passwd_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<PasswdEntry>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        if let Ok(line) = line {
            if let Some(entry) = PasswdEntry::from_line(&line) {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}


#[tokio::main]
async fn main() -> Result<()> {
    let db = CustomDataSource {
        data: read_passwd_file("/etc/passwd").expect("Error while reading passwd file"),
        schema: SchemaRef::new(Schema::new(vec![
            Field::new("username", DataType::Utf8, false),
            Field::new("password", DataType::Utf8, false),
            Field::new("uid", DataType::UInt32, false),
            Field::new("gid", DataType::UInt32, false),
            Field::new("description", DataType::Utf8, false),
            Field::new("home_directory", DataType::Utf8, false),
            Field::new("shell", DataType::Utf8, false),
        ]), ),
    };

    let ctx = SessionContext::new();
    _ = ctx.register_table("users", Arc::new(db.clone()));
    // TODO: Below one fails with: index out of bounds: the len is 5 but the index is 5
    // let df = ctx.sql("SELECT username, uid, description, home_directory, shell FROM users WHERE shell NOT LIKE '%false%'").await?;
    let df = ctx.sql("SELECT * FROM users WHERE shell NOT LIKE '%false%'").await?;
    df.show().await.expect("Error while displaying the dataframe");
    Ok(())
}


#[async_trait]
impl TableProvider for CustomDataSource {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        _state: &SessionState,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        return self.create_physical_plan(projection, filters, limit, self.schema()).await;
    }
}


#[derive(Clone, Debug)]
struct User {
    id: u8,
    bank_account: u64,
}

#[derive(Clone)]
pub struct CustomDataSource {
    data: Vec<PasswdEntry>,
    schema: SchemaRef,
}

impl Debug for CustomDataSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("custom_db")
    }
}

impl CustomDataSource {
    pub(crate) async fn create_physical_plan(
        &self,
        projections: Option<&Vec<usize>>,
        _filters: &[Expr],
        _limit: Option<usize>,
        schema: SchemaRef,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        Ok(Arc::new(CustomExec::new(projections, schema, self.clone())))
    }
}


impl ExecutionPlan for CustomExec {
    fn name(&self) -> &'static str {
        "CustomExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn properties(&self) -> &PlanProperties {
        &self.cache
    }

    fn children(&self) -> Vec<Arc<(dyn ExecutionPlan + 'static)>> {
        vec![]
    }

    fn with_new_children(
        self: Arc<Self>,
        _: Vec<Arc<dyn ExecutionPlan>>,
    ) -> datafusion_common::Result<Arc<dyn ExecutionPlan>> {
        Ok(self)
    }

    fn execute(
        &self,
        _partition: usize,
        _context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        let result = self.get_data()?;
        Ok(Box::pin(result?))
    }
}


#[derive(Debug, Clone)]
struct CustomExec {
    db: CustomDataSource,
    projected_schema: SchemaRef,
    cache: PlanProperties,
    projections: Option<Vec<usize>>,
}

impl CustomExec {
    fn new(
        projections: Option<&Vec<usize>>,
        schema: SchemaRef,
        db: CustomDataSource,
    ) -> Self {
        let projected_schema = project_schema(&schema, projections).unwrap();
        // TODO: I changed this to schema because otherwise projections don't work
        let cache = Self::compute_properties(schema.clone());
        Self {
            db,
            projected_schema,
            cache,
            projections: projections.cloned(),
        }
    }

    fn compute_properties(schema: SchemaRef) -> PlanProperties {
        let eq_properties = EquivalenceProperties::new(schema);
        PlanProperties::new(
            eq_properties,
            Partitioning::UnknownPartitioning(1),
            ExecutionMode::Bounded,
        )
    }

    fn get_data(&self) -> Result<Result<MemoryStream>, DataFusionError> {
        let data: Vec<PasswdEntry> = self.db.data.clone();
        if data.len() == 0 {
            return Ok(Ok(MemoryStream::try_new(
                vec![],
                self.projected_schema.clone(),
                self.projections.clone(),
            )?));
        }


        let mut username_array = StringBuilder::new();
        let mut password_array = StringBuilder::new();
        let mut uid_array = UInt32Builder::with_capacity(data.len());
        let mut gid_array = UInt32Builder::with_capacity(data.len());
        let mut description_array = StringBuilder::new();
        let mut home_directory_array = StringBuilder::new();
        let mut shell_array = StringBuilder::new();

        for datum in data {
            username_array.append_value(&datum.username);
            password_array.append_value(&datum.password);
            uid_array.append_value(datum.uid);
            gid_array.append_value(datum.gid);
            description_array.append_value(&datum.description);
            home_directory_array.append_value(&datum.home_directory);
            shell_array.append_value(&datum.shell);
        }

        Ok(MemoryStream::try_new(
            vec![RecordBatch::try_new(
                self.schema().clone(),
                vec![
                    Arc::new(username_array.finish()),
                    Arc::new(password_array.finish()),
                    Arc::new(uid_array.finish()),
                    Arc::new(gid_array.finish()),
                    Arc::new(description_array.finish()),
                    Arc::new(home_directory_array.finish()),
                    Arc::new(shell_array.finish()),
                ],
            )?],
            self.schema().clone(),
            self.projections.clone(),
        ))
    }
}

impl DisplayAs for CustomExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter) -> std::fmt::Result {
        write!(f, "CustomExec")
    }
}





